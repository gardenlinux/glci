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
func (p *Publisher) Publish(ctx context.Context, version, commit string, omitComponentDescritpr bool) error {
	ctx = log.WithValues(ctx, "op", "publish", "version", version, "commit", commit)

	ctx = task.WithStatePersistor(ctx, p.state, id(version, commit))
	err := p.publish(ctx, version, commit, omitComponentDescritpr)
	stateErr := task.PersistorError(ctx)
	if stateErr != nil {
		log.ErrorMsg(ctx, "State could not be saved! Please investigate manually before rerunning GLCI!")
		if err == nil {
			err = stateErr
		}
	}
	return err
}

func (p *Publisher) publish(ctx context.Context, version, commit string, omitComponentDescritpr bool) error {
	rollbackHandlers := make([]task.RollbackHandler, 0, len(p.targets))
	for _, target := range p.targets {
		rollbackHandlers = append(rollbackHandlers, target)
	}
	err := task.Rollback(ctx, rollbackHandlers)
	if err != nil {
		return fmt.Errorf("cannot roll back: %w", err)
	}

	glciVer := cli.Version(ctx)

	publications := make([]cloudprovider.Publication, len(p.flavors))
	expandCommit := sync.Once{}
	fetchManifests := parallel.NewActivitySync(ctx)
	for i, flavor := range p.flavors {
		fetchManifests.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", flavor.Cname, version, commit)
			ctx = log.WithValues(ctx, "cname", flavor.Cname, "platform", flavor.Platform)

			log.Info(ctx, "Retrieving manifest")
			manifest, er := cloudprovider.GetManifest(ctx, p.manifestSource, manifestKey)
			if er != nil {
				return nil, fmt.Errorf("cannot get manifest for %s: %w", flavor.Cname, er)
			}
			if manifest.Version != version {
				return nil, fmt.Errorf("manifest for %s has incorrect version %s", flavor.Cname, manifest.Version)
			}
			if manifest.BuildCommittish != commit && fmt.Sprintf("%.8s", manifest.BuildCommittish) != commit {
				return nil, fmt.Errorf("manifest for %s has incorrect commit %s", flavor.Cname, manifest.BuildCommittish)
			}
			expandCommit.Do(func() {
				commit = manifest.BuildCommittish
			})

			log.Debug(ctx, "Retrieving target manifest")
			var targetManifest *gardenlinux.Manifest
			targetManifest, er = cloudprovider.GetManifest(ctx, p.manifestTarget, manifestKey)
			_, ok := errors.AsType[cloudprovider.KeyNotFoundError](er)
			if er != nil && !ok {
				return nil, fmt.Errorf("cannot get target manifest for %s: %w", flavor.Cname, er)
			}
			if targetManifest != nil {
				if targetManifest.Version != version {
					return nil, fmt.Errorf("target manifest for %s has incorrect version %s", flavor.Cname, targetManifest.Version)
				}
				if targetManifest.BuildCommittish != commit {
					return nil, fmt.Errorf("target manifest for %s has incorrect commit %s", flavor.Cname,
						targetManifest.BuildCommittish)
				}

				manifest = targetManifest
			}

			for _, target := range p.targets {
				if target.CanPublish(manifest) {
					return func() error {
						publications[i] = cloudprovider.Publication{
							Cname:    flavor.Cname,
							Manifest: manifest,
							Target:   target,
						}

						return nil
					}, nil
				}
			}

			return nil, fmt.Errorf("no publishing target for %s", flavor.Cname)
		})
	}
	err = fetchManifests.Wait()
	if err != nil {
		return err
	}

	var descriptor *ocm.ComponentDescriptor
	descriptor, err = ocm.BuildComponentDescriptor(ctx, p.manifestSource, publications, p.ocmTarget, p.aliases, glciVer, version, commit)
	if err != nil {
		return fmt.Errorf("cannot build component descriptor: %w", err)
	}

	log.Info(ctx, "Publishing images", "count", len(publications))
	publishPublications := parallel.NewActivity(ctx)
	for i, publication := range publications {
		publishPublications.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "cname", publication.Cname, "platform", publication.Target.Type())

			uptime := cli.ExecTime(ctx)
			if uptime != 0 && uptime.Hours() > 5 {
				return errors.New("publishing taking too long, restart GLCI to resume")
			}

			isPublished, er := publication.Target.IsPublished(publication.Manifest)
			if er != nil {
				return fmt.Errorf("cannot determine publishing status for %s: %w", publication.Cname, err)
			}
			if isPublished {
				log.Info(ctx, "Already published, skipping")
				return nil
			}
			ctx = task.WithDomain(task.WithUndeadMode(task.WithBatch(ctx, publication.Cname), true), publication.Target.CanRollback())

			log.Info(ctx, "Publishing image")
			publication.Manifest.PublishedImageMetadata, er = publication.Target.Publish(ctx, publication.Cname, publication.Manifest)
			if er != nil {
				return fmt.Errorf("cannot publish %s to %s: %w", publication.Cname, publication.Target.Type(), er)
			}

			if glciVer != "" {
				publication.Manifest.GLCIVersion = glciVer
			}

			log.Info(ctx, "Updating manifest")
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", publication.Cname, version, commit)
			task.RemoveCompleted(ctx, publication.Cname)
			er = cloudprovider.PutManifest(ctx, p.manifestTarget, manifestKey, publication.Manifest)
			if er != nil {
				return fmt.Errorf("cannot put manifest for %s: %w", publication.Cname, er)
			}

			publications[i] = publication
			return nil
		})
	}
	err = publishPublications.Wait()
	if err != nil {
		return err
	}

	task.Clear(ctx)
	stateErr := task.PersistorError(ctx)
	if stateErr != nil {
		return fmt.Errorf("cannot maintain state: %w", stateErr)
	}

	if !omitComponentDescritpr {
		log.Debug(ctx, "Finalizing component descriptor")
		err = ocm.AddPublicationOutput(descriptor, publications)
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

func id(version, commit string) string {
	return fmt.Sprintf("%s-%.8s", version, commit)
}
