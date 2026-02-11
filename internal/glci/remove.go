package glci

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/task"
)

// Remove removes a release from all cloud providers specified in the flavors and publishing configurations.
func Remove(ctx context.Context, flavorsConfig FlavorsConfig, publishingConfig PublishingConfig, version, commit string,
	steamroll bool,
) error {
	ctx = log.WithValues(ctx, "op", "remove", "version", version, "commit", commit)

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

	rollbackHandlers := make([]task.RollbackHandler, 0, len(targets))
	for _, target := range targets {
		rollbackHandlers = append(rollbackHandlers, target)
	}
	err = task.Rollback(ctx, rollbackHandlers)
	if err != nil {
		return fmt.Errorf("cannot roll back: %w", err)
	}

	task.Clear(ctx)
	err = task.PersistorError(ctx)
	if err != nil {
		log.ErrorMsg(ctx, "State could not be saved! Please investigate manually before rerunning GLCI!")
		return fmt.Errorf("cannot maintain state: %w", err)
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
				manifest, er := cloudprovider.GetManifest(ctx, manifestTarget, manifestKey)
				if er != nil {
					if errors.As(er, &cloudprovider.KeyNotFoundError{}) && manifestTarget != manifestSource {
						log.Debug(ctx, "Manifest not found, skipping")
						return nil, nil
					}
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

	if len(publications) > 0 {
		log.Info(ctx, "Removing images", "count", len(publications))
	} else {
		log.Info(ctx, "Nothing to remove")
	}

	removePublications := parallel.NewActivitySync(ctx)
	for _, publication := range publications {
		removePublications.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			ctx = log.WithValues(ctx, "cname", publication.Cname, "platform", publication.Target.Type())

			isPublished, er := publication.Target.IsPublished(publication.Manifest)
			if er != nil {
				return nil, fmt.Errorf("cannot determine publishing status for %s: %w", publication.Cname, er)
			}
			if !isPublished {
				log.Info(ctx, "Already removed, skipping")
				return nil, nil
			}

			log.Info(ctx, "Removing image")
			er = publication.Target.Remove(ctx, publication.Manifest, sources, steamroll)
			if er != nil {
				return nil, fmt.Errorf("cannot remove %s from %s: %w", publication.Cname, publication.Target.Type(), er)
			}

			return func() error {
				publication.Manifest = publications[pubMap[publication.Cname][0]].Manifest
				var output cloudprovider.PublishingOutput
				output, er = publication.Target.RemoveOwnPublishingOutput(publication.Manifest.PublishedImageMetadata)
				if err != nil {
					return fmt.Errorf("cannot remove publishing output for %s: %w", publication.Cname, er)
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
				er = cloudprovider.PutManifest(ctx, manifestTarget, manifestKey, publication.Manifest)
				if er != nil {
					return fmt.Errorf("cannot put manifest for %s: %w", publication.Cname, er)
				}

				return nil
			}, nil
		})
	}
	err = removePublications.Wait()
	if err != nil {
		return err
	}

	log.Debug(ctx, "Closing sources and targets")
	err = closeSourcesAndTargetsAndPersistors(credsSource, sources, targets, ocmTarget, state)
	if err != nil {
		return fmt.Errorf("cannot close sources and targets: %w", err)
	}

	log.Info(ctx, "Removing completed successfully")
	return nil
}
