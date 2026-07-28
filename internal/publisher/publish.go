package publisher

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gardenlinux/glci/internal/cli"
	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ocm"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/task"
)

// Publish publishes a release to all configured cloud providers.
func (p *Publisher) Publish(ctx context.Context, version, commit string, omitIrreversible, omitComponentDescriptor bool) error {
	ctx = log.WithValues(ctx, "op", "publish", "version", version, "commit", commit)

	ctx = task.WithStatePersistor(ctx, p.state, id(version, commit))
	err := p.publish(ctx, version, commit, omitIrreversible, omitComponentDescriptor)
	stateErr := task.PersistorError(ctx)
	if stateErr != nil {
		log.ErrorMsg(ctx, "State could not be saved! Please investigate manually before rerunning GLCI!")
		if err == nil {
			err = stateErr
		}
	}
	return err
}

func (p *Publisher) publish(ctx context.Context, version, commit string, omitIrreversible, omitComponentDescriptor bool) error {
	rollbackHandlers := make([]task.RollbackHandler, 0, len(p.targets))
	for _, target := range p.targets {
		if !target.CanUnpublish() {
			continue
		}

		rollbackHandlers = append(rollbackHandlers, target)
	}
	err := task.Rollback(ctx, rollbackHandlers)
	if err != nil {
		return fmt.Errorf("cannot roll back: %w", err)
	}

	glciVer := cli.Version(ctx)

	publications := make([]publication, len(p.flavors))
	expandCommit := sync.Once{}
	fetchManifests := parallel.NewActivitySync(ctx)
	for i, flavorConfig := range p.flavors {
		fetchManifests.Go(func(ctx context.Context) (parallel.ResultSyncFunc, error) {
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", flavorConfig.Flavor, version, commit)
			ctx = log.WithValues(ctx, "flavor", flavorConfig.Flavor)

			log.Info(ctx, "Retrieving manifest")
			manifest, er := cloudprovider.GetManifest(ctx, p.manifestSource, manifestKey)
			if er != nil {
				return nil, fmt.Errorf("cannot get manifest for %s: %w", flavorConfig.Flavor, er)
			}
			if manifest.Version != version {
				return nil, fmt.Errorf("manifest for %s has incorrect version %s", flavorConfig.Flavor, manifest.Version)
			}
			if manifest.BuildCommittish != commit && fmt.Sprintf("%.8s", manifest.BuildCommittish) != commit {
				return nil, fmt.Errorf("manifest for %s has incorrect commit %s", flavorConfig.Flavor, manifest.BuildCommittish)
			}
			expandCommit.Do(func() {
				commit = manifest.BuildCommittish
			})

			log.Debug(ctx, "Retrieving target manifest")
			var targetManifest *gardenlinux.Manifest
			targetManifest, er = cloudprovider.GetManifest(ctx, p.manifestTarget, manifestKey)
			_, ok := errors.AsType[cloudprovider.KeyNotFoundError](er)
			if er != nil && !ok {
				return nil, fmt.Errorf("cannot get target manifest for %s: %w", flavorConfig.Flavor, er)
			}
			if targetManifest != nil {
				if targetManifest.Version != version {
					return nil, fmt.Errorf("target manifest for %s has incorrect version %s", flavorConfig.Flavor, targetManifest.Version)
				}
				if targetManifest.BuildCommittish != commit {
					return nil, fmt.Errorf("target manifest for %s has incorrect commit %s", flavorConfig.Flavor,
						targetManifest.BuildCommittish)
				}

				manifest = targetManifest
			}

			var target cloudprovider.PublishingTarget
			target, er = p.selectTarget(manifest, flavorConfig.Flavor)
			if er != nil {
				return nil, er
			}
			return func() error {
				publications[i] = publication{
					FlavorManifest: gardenlinux.FlavorManifest{
						Flavor:      flavorConfig.Flavor,
						Manifest:    manifest,
						ImageSuffix: target.ImageSuffix(),
					},
					Target:                target,
					CloudProfile:          flavorConfig.CloudProfile,
					InComponentDescriptor: flavorConfig.InComponentDescriptor,
				}

				return nil
			}, nil
		})
	}
	err = fetchManifests.Wait()
	if err != nil {
		return err
	}

	manifestsInDescriptor := make([]gardenlinux.FlavorManifest, 0, len(publications))
	for _, publication := range publications {
		if publication.InComponentDescriptor {
			manifestsInDescriptor = append(manifestsInDescriptor, publication.FlavorManifest)
		}
	}

	var descriptor *ocm.ComponentDescriptor
	descriptor, err = ocm.BuildComponentDescriptor(ctx, p.manifestSource, manifestsInDescriptor, p.ocmTarget, p.aliases, glciVer, version,
		commit)
	if err != nil {
		return fmt.Errorf("cannot build component descriptor: %w", err)
	}

	log.Info(ctx, "Publishing images", "count", len(publications))
	notUnpublishablePublications := make([]publication, 0, len(publications))
	publishPublication := parallel.NewActivity(ctx)
	for _, publication := range publications {
		if !publication.Target.CanUnpublish() {
			notUnpublishablePublications = append(notUnpublishablePublications, publication)
			continue
		}

		publishPublication.Go(func(ctx context.Context) error {
			return p.publishPublication(ctx, publication, version, commit, glciVer)
		})
	}
	err = publishPublication.Wait()
	if err != nil {
		return err
	}

	task.Clear(ctx)
	stateErr := task.PersistorError(ctx)
	if stateErr != nil {
		return fmt.Errorf("cannot maintain state: %w", stateErr)
	}

	if omitIrreversible {
		if len(notUnpublishablePublications) > 0 {
			log.Info(ctx, "Skipping targets that cannot be unpublished", "count", len(notUnpublishablePublications))
		}
	} else {
		publishPublication = parallel.NewActivity(ctx)
		for _, publication := range notUnpublishablePublications {
			publishPublication.Go(func(ctx context.Context) error {
				return p.publishPublication(ctx, publication, version, commit, glciVer)
			})
		}
		err = publishPublication.Wait()
		if err != nil {
			return err
		}
	}

	if omitIrreversible || omitComponentDescriptor {
		log.Info(ctx, "Skipping component descriptor")
	} else {
		log.Debug(ctx, "Finalizing component descriptor")
		err = ocm.AddPublicationOutput(descriptor, manifestsInDescriptor)
		if err != nil {
			return fmt.Errorf("cannot add publication output to component descriptor: %w", err)
		}

		var descriptorYAML []byte
		descriptorYAML, err = descriptor.ToYAML()
		if err != nil {
			return fmt.Errorf("invalid component descriptor: %w", err)
		}

		ctx = log.WithValues(ctx, "ocmRepoBase", p.ocmTarget.OCMRepositoryBase())
		log.Info(ctx, "Publishing component descriptor")
		err = p.ocmTarget.PublishComponentDescriptor(ctx, version, descriptorYAML)
		if err != nil {
			return fmt.Errorf("cannot publish component descriptor: %w", err)
		}
	}

	log.Info(ctx, "Publishing completed successfully")
	return nil
}

func (p *Publisher) publishPublication(ctx context.Context, publication publication, version, commit, glciVer string) error {
	ctx = log.WithValues(ctx, "flavor", publication.Flavor, "targetType", publication.Target.Type())

	uptime := cli.ExecTime(ctx)
	if uptime != 0 && uptime.Hours() > 5 {
		return errors.New("publishing taking too long, restart to resume")
	}

	isPublished, err := publication.Target.IsPublished(publication.Manifest)
	if err != nil {
		return fmt.Errorf("cannot determine publishing status for %s: %w", publication.Flavor, err)
	}
	if isPublished {
		log.Info(ctx, "Already published, skipping")
		return nil
	}
	ctx = task.WithDomain(task.WithUndeadMode(task.WithBatch(ctx, publication.Flavor), true), publication.Target.RollbackDomain())

	log.Info(ctx, "Publishing image")
	publication.Manifest.PublishedImageMetadata, err = publication.Target.Publish(ctx, publication.Flavor, publication.Manifest)
	if err != nil {
		return fmt.Errorf("cannot publish %s to %s: %w", publication.Flavor, publication.Target.Type(), err)
	}

	if glciVer != "" {
		publication.Manifest.GLCIVersion = glciVer
	}

	log.Info(ctx, "Updating manifest")
	manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", publication.Flavor, version, commit)
	task.RemoveCompleted(ctx, publication.Flavor)
	err = cloudprovider.PutManifest(ctx, p.manifestTarget, manifestKey, publication.Manifest)
	if err != nil {
		return fmt.Errorf("cannot put manifest for %s: %w", publication.Flavor, err)
	}

	return nil
}

func id(version, commit string) string {
	return fmt.Sprintf("%s-%.8s", version, commit)
}
