package publisher

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gardenlinux/glci/internal/cli"
	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/task"
)

// Remove removes a release from all configured cloud providers.
func (p *Publisher) Remove(ctx context.Context, version, commit string, steamroll bool) error {
	ctx = log.WithValues(ctx, "op", "remove", "version", version, "commit", commit)

	ctx = task.WithStatePersistor(ctx, p.state, id(version, commit))

	rollbackHandlers := make([]task.RollbackHandler, 0, len(p.targets))
	for _, target := range p.targets {
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

	publications := make([]cloudprovider.Publication, len(p.flavors))
	expandCommit := sync.Once{}
	fetchManifests := parallel.NewActivitySync(ctx)
	for i, flavor := range p.flavors {
		fetchManifests.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", flavor.Cname, version, commit)
			ctx = log.WithValues(ctx, "cname", flavor.Cname, "platform", flavor.Platform)

			log.Info(ctx, "Retrieving manifest")
			manifest, er := cloudprovider.GetManifest(ctx, p.manifestTarget, manifestKey)
			if er != nil {
				_, ok := errors.AsType[cloudprovider.KeyNotFoundError](er)
				if ok && p.manifestTarget != p.manifestSource {
					return func() error {
						publications[i] = cloudprovider.Publication{
							Cname: flavor.Cname,
						}

						return nil
					}, nil
				}
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

	log.Info(ctx, "Removing images", "count", len(publications))
	removePublications := parallel.NewLimitedActivity(ctx, 7)
	for i, publication := range publications {
		if publication.Manifest == nil {
			lctx := log.WithValues(ctx, "cname", publication.Cname)
			log.Info(lctx, "Already removed, skipping")
			continue
		}

		removePublications.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "cname", publication.Cname, "platform", publication.Target.Type())

			isPublished, er := publication.Target.IsPublished(publication.Manifest)
			if er != nil {
				return fmt.Errorf("cannot determine publishing status for %s: %w", publication.Cname, er)
			}
			if !isPublished {
				log.Info(ctx, "Already removed, skipping")
				return nil
			}

			log.Info(ctx, "Removing image")
			er = publication.Target.Remove(ctx, publication.Manifest, steamroll)
			if er != nil {
				return fmt.Errorf("cannot remove %s from %s: %w", publication.Cname, publication.Target.Type(), er)
			}
			publication.Manifest.PublishedImageMetadata = nil

			if glciVer != "" {
				publication.Manifest.GLCIVersion = glciVer
			}

			log.Info(ctx, "Updating manifest")
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", publication.Cname, version, commit)
			er = cloudprovider.PutManifest(ctx, p.manifestTarget, manifestKey, publication.Manifest)
			if er != nil {
				return fmt.Errorf("cannot put manifest for %s: %w", publication.Cname, er)
			}

			publications[i] = publication
			return nil
		})
	}
	err = removePublications.Wait()
	if err != nil {
		return err
	}

	log.Info(ctx, "Removing completed successfully")
	return nil
}
