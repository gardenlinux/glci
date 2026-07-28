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
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/task"
)

// Unpublish unpublishes a release from all configured cloud providers.
func (p *Publisher) Unpublish(ctx context.Context, version, commit string, steamroll bool) error {
	ctx = log.WithValues(ctx, "op", "unpublish", "version", version, "commit", commit)

	ctx = task.WithStatePersistor(ctx, p.state, id(version, commit))

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

	task.Clear(ctx)
	err = task.PersistorError(ctx)
	if err != nil {
		log.ErrorMsg(ctx, "State could not be saved! Please investigate manually before rerunning GLCI!")
		return fmt.Errorf("cannot maintain state: %w", err)
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
			manifest, er := cloudprovider.GetManifest(ctx, p.manifestTarget, manifestKey)
			if er != nil {
				_, ok := errors.AsType[cloudprovider.KeyNotFoundError](er)
				if ok && p.manifestTarget != p.manifestSource {
					return func() error {
						publications[i] = publication{
							FlavorManifest: gardenlinux.FlavorManifest{
								Flavor: flavorConfig.Flavor,
							},
						}

						return nil
					}, nil
				}
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
					Target: target,
				}

				return nil
			}, nil
		})
	}
	err = fetchManifests.Wait()
	if err != nil {
		return err
	}

	log.Info(ctx, "Unpublishing images", "count", len(publications))
	unpublishPublications := parallel.NewLimitedActivity(ctx, 7)
	for i, pub := range publications {
		if pub.Manifest == nil {
			lctx := log.WithValues(ctx, "flavor", pub.Flavor)
			log.Info(lctx, "Already unpublished, skipping")
			continue
		}
		if !pub.Target.CanUnpublish() {
			lctx := log.WithValues(ctx, "flavor", pub.Flavor, "targetType", pub.Target.Type())
			log.Info(lctx, "Target cannot be unpublished, skipping")
			continue
		}
		unpublishPublications.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "flavor", pub.Flavor, "targetType", pub.Target.Type())

			isPublished, er := pub.Target.IsPublished(pub.Manifest)
			if er != nil {
				return fmt.Errorf("cannot determine publishing status for %s: %w", pub.Flavor, er)
			}
			if !isPublished {
				log.Info(ctx, "Already unpublished, skipping")
				return nil
			}

			log.Info(ctx, "Unpublishing image")
			er = pub.Target.Unpublish(ctx, pub.Manifest, steamroll)
			if er != nil {
				return fmt.Errorf("cannot unpublish %s from %s: %w", pub.Flavor, pub.Target.Type(), er)
			}
			pub.Manifest.PublishedImageMetadata = nil

			if glciVer != "" {
				pub.Manifest.GLCIVersion = glciVer
			}

			log.Info(ctx, "Updating manifest")
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", pub.Flavor, version, commit)
			er = cloudprovider.PutManifest(ctx, p.manifestTarget, manifestKey, pub.Manifest)
			if er != nil {
				return fmt.Errorf("cannot put manifest for %s: %w", pub.Flavor, er)
			}

			publications[i] = pub
			return nil
		})
	}
	err = unpublishPublications.Wait()
	if err != nil {
		return err
	}

	log.Info(ctx, "Unpublishing completed successfully")
	return nil
}
