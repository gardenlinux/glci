package glci

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ocm"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/task"
)

// Publish publishes a release to all cloud providers specified in the flavors and publishing configurations.
func Publish(ctx context.Context, flavorsConfig FlavorsConfig, publishingConfig PublishingConfig, aliasesConfig AliasesConfig, version,
	commit string, omitComponentDescritpr bool,
) error {
	ctx = log.WithValues(ctx, "op", "publish", "version", version, "commit", commit)

	log.Debug(ctx, "Loading configuration")
	credsSource, manifestSource, manifestTarget, sources, targets, ocmTarget, state, err := loadConfig(ctx, publishingConfig)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	defer func() {
		_ = closeSourcesAndTargetsAndPersistors(credsSource, sources, targets, ocmTarget, state)
		_ = manifestSource.Close()
		_ = manifestTarget.Close()
	}()
	ctx = task.WithStatePersistor(ctx, state, id(version, commit))

	err = publish(ctx, flavorsConfig, aliasesConfig, credsSource, manifestSource, manifestTarget, sources, targets, ocmTarget, state,
		version, commit, omitComponentDescritpr)
	perr := task.PersistorError(ctx)
	if perr != nil {
		log.ErrorMsg(ctx, "State could not be saved! Please investigate manually before rerunning GLCI!")
		if err == nil {
			err = perr
		}
	}
	return err
}

func publish(ctx context.Context, flavorsConfig FlavorsConfig, aliasesConfig AliasesConfig, credsSource credsprovider.CredsSource,
	manifestSource, manifestTarget cloudprovider.ArtifactSource, sources map[string]cloudprovider.ArtifactSource,
	targets []cloudprovider.PublishingTarget, ocmTarget cloudprovider.OCMTarget, state task.StatePersistor, version, commit string,
	omitComponentDescritpr bool,
) error {
	rollbackHandlers := make([]task.RollbackHandler, 0, len(targets))
	for _, target := range targets {
		rollbackHandlers = append(rollbackHandlers, target)
	}
	err := task.Rollback(ctx, rollbackHandlers)
	if err != nil {
		return fmt.Errorf("cannot roll back: %w", err)
	}

	glciVer := glciVersion(ctx)
	publications := make([]cloudprovider.Publication, 0, len(flavorsConfig.Flavors)*2)
	pubMap := make(map[string][]int, len(flavorsConfig.Flavors))
	fetchManifests := parallel.NewActivitySync(ctx)

	expandCommit := sync.Once{}
	for _, flavor := range flavorsConfig.Flavors {
		found := false

		for _, target := range targets {
			if target.Type() != flavor.Platform {
				continue
			}
			found = true
			origCommit := commit

			fetchManifests.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
				manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", flavor.Cname, version, origCommit)
				ctx = log.WithValues(ctx, "cname", flavor.Cname, "platform", flavor.Platform)

				log.Info(ctx, "Retrieving manifest")
				manifest, er := cloudprovider.GetManifest(ctx, manifestSource, manifestKey)
				if er != nil {
					return nil, fmt.Errorf("cannot get manifest for %s: %w", flavor.Cname, er)
				}
				if manifest.Version != version {
					return nil, fmt.Errorf("manifest for %s has incorrect version %s", flavor.Cname, manifest.Version)
				}
				if manifest.BuildCommittish != origCommit && fmt.Sprintf("%.8s", manifest.BuildCommittish) != origCommit {
					return nil, fmt.Errorf("manifest for %s has incorrect commit %s", flavor.Cname, manifest.BuildCommittish)
				}
				expandCommit.Do(func() {
					commit = manifest.BuildCommittish
				})

				if !target.CanPublish(manifest) {
					return nil, nil
				}

				log.Debug(ctx, "Retrieving target manifest")
				var targetManifest *gl.Manifest
				targetManifest, er = cloudprovider.GetManifest(ctx, manifestTarget, manifestKey)
				if er != nil && !errors.As(er, &cloudprovider.KeyNotFoundError{}) {
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

					if !target.CanPublish(targetManifest) {
						return nil, errors.New("target manifest does not correspond to source manifest")
					}

					manifest = targetManifest
				}

				publication := cloudprovider.Publication{
					Cname:    flavor.Cname,
					Manifest: manifest,
					Target:   target,
				}

				return func() error {
					publications = append(publications, publication)
					pubMap[publication.Cname] = append(pubMap[publication.Cname], len(publications)-1)

					return nil
				}, nil
			})
		}

		if !found {
			return fmt.Errorf("no publishing target for %s", flavor.Cname)
		}
	}
	err = fetchManifests.Wait()
	if err != nil {
		return err
	}

	cdPublications := make([]cloudprovider.Publication, 0, len(flavorsConfig.Flavors))
	for _, j := range pubMap {
		cdPublications = append(cdPublications, publications[j[0]])
	}

	var descriptor *ocm.ComponentDescriptor
	descriptor, err = ocm.BuildComponentDescriptor(ctx, manifestSource, cdPublications, ocmTarget, aliasesConfig, glciVer, version, commit)
	if err != nil {
		return fmt.Errorf("cannot build component descriptor: %w", err)
	}

	if len(publications) > 0 {
		log.Info(ctx, "Publishing images", "count", len(publications))
	} else {
		log.Info(ctx, "Nothing to publish")
	}

	publishPublications := parallel.NewActivitySync(ctx)
	for _, publication := range publications {
		publishPublications.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			ctx = log.WithValues(ctx, "cname", publication.Cname, "platform", publication.Target.Type())

			uptime := execTime(ctx)
			if uptime != 0 && uptime.Hours() > 5 {
				return nil, errors.New("publishing taking too long, restart GLCI to resume")
			}

			isPublished, er := publication.Target.IsPublished(publication.Manifest)
			if er != nil {
				return nil, fmt.Errorf("cannot determine publishing status for %s: %w", publication.Cname, err)
			}
			if isPublished {
				log.Info(ctx, "Already published, skipping")
				return nil, nil
			}
			ctx = task.WithDomain(ctx, publication.Target.CanRollback())
			ctx = task.WithBatch(ctx, publication.Cname)
			ctx = task.WithUndeadMode(ctx, true)

			log.Info(ctx, "Publishing image")
			var output cloudprovider.PublishingOutput
			output, er = publication.Target.Publish(ctx, publication.Cname, publication.Manifest, sources)
			if er != nil {
				return nil, fmt.Errorf("cannot publish %s to %s: %w", publication.Cname, publication.Target.Type(), er)
			}

			return func() error {
				publication.Manifest = publications[pubMap[publication.Cname][0]].Manifest
				output, er = publication.Target.AddOwnPublishingOutput(publication.Manifest.PublishedImageMetadata, output)
				if er != nil {
					return fmt.Errorf("cannot add publishing output for %s: %w", publication.Cname, er)
				}
				publication.Manifest.PublishedImageMetadata = output
				if glciVer != "" {
					publication.Manifest.GLCIVersion = glciVer
				}
				for _, i := range pubMap[publication.Cname] {
					publications[i].Manifest = publication.Manifest
				}

				log.Info(ctx, "Updating manifest")
				manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", publication.Cname, version, commit)
				task.RemoveCompleted(ctx, publication.Cname)
				er = cloudprovider.PutManifest(ctx, manifestTarget, manifestKey, publication.Manifest)
				if er != nil {
					return fmt.Errorf("cannot put manifest for %s: %w", publication.Cname, er)
				}

				return nil
			}, nil
		})
	}
	err = publishPublications.Wait()
	if err != nil {
		return err
	}

	task.Clear(ctx)
	perr := task.PersistorError(ctx)
	if perr != nil {
		return fmt.Errorf("cannot maintain state: %w", perr)
	}

	if !omitComponentDescritpr {
		for i, publication := range cdPublications {
			cdPublications[i].Manifest = publications[pubMap[publication.Cname][0]].Manifest
		}

		log.Debug(ctx, "Finalizing component descriptor")
		err = ocm.AddPublicationOutput(descriptor, cdPublications)
		if err != nil {
			return fmt.Errorf("cannot add publication output to component descriptor: %w", err)
		}

		var descriptorYAML []byte
		descriptorYAML, err = descriptor.ToYAML()
		if err != nil {
			return fmt.Errorf("invalid component descriptor: %w", err)
		}

		ctx = log.WithValues(ctx, "ocmRepoBase", ocmTarget.OCMRepositoryBase())
		log.Info(ctx, "Publishing component descriptor")
		err = ocmTarget.PublishComponentDescriptor(ctx, version, descriptorYAML)
		if err != nil {
			return fmt.Errorf("cannot publish component descriptor: %w", err)
		}
	}

	log.Debug(ctx, "Closing sources and targets")
	err = closeSourcesAndTargetsAndPersistors(credsSource, sources, targets, ocmTarget, state)
	if err != nil {
		return fmt.Errorf("cannot close sources and targets: %w", err)
	}

	log.Info(ctx, "Publishing completed successfully")
	return nil
}
