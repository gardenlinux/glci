package glci

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ocm"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/task"
)

// Publish publishes a release to all cloud providers specified in the flavors and publishing configurations.
func Publish(ctx context.Context, flavorsConfig FlavorsConfig, publishingConfig PublishingConfig, aliasesConfig AliasesConfig,
	creds Credentials, version, commit string, omitComponentDescritpr bool,
) error {
	ctx = log.WithValues(ctx, "op", "publish", "version", version, "commit", commit)

	log.Debug(ctx, "Loading credentials and configuration")
	manifestSource, manifestTarget, sources, targets, ocmTarget, state, err := loadCredentialsAndConfig(ctx, creds, publishingConfig)
	if err != nil {
		return fmt.Errorf("invalid credentials or configuration: %w", err)
	}
	defer func() {
		_ = closeSourcesAndTargetsAndPersistors(sources, targets, ocmTarget, state)
	}()
	ctx = task.WithStatePersistor(ctx, state, id(version, commit))

	err = publish(ctx, flavorsConfig, aliasesConfig, manifestSource, manifestTarget, sources, targets, ocmTarget, state, version, commit,
		omitComponentDescritpr)
	perr := task.PersistorError(ctx)
	if perr != nil {
		log.ErrorMsg(ctx, "State could not be saved! Please investigate manually before rerunning GLCI!")
		if err == nil {
			err = perr
		}
	}
	if err != nil {
		return err
	}

	return nil
}

func publish(ctx context.Context, flavorsConfig FlavorsConfig, aliasesConfig AliasesConfig, manifestSource,
	manifestTarget cloudprovider.ArtifactSource, sources map[string]cloudprovider.ArtifactSource, targets []cloudprovider.PublishingTarget,
	ocmTarget cloudprovider.OCMTarget, state task.StatePersistor, version, commit string, omitComponentDescritpr bool,
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
	fetchManifests := parallel.NewActivity(ctx, func(_ context.Context, publication *cloudprovider.Publication) error {
		if publication == nil {
			return nil
		}

		publications = append(publications, *publication)
		pubMap[publication.Cname] = append(pubMap[publication.Cname], len(publications)-1)

		return nil
	})

	expandCommit := sync.Once{}
	for _, flavor := range flavorsConfig.Flavors {
		found := false

		for _, target := range targets {
			if target.Type() != flavor.Platform {
				continue
			}
			found = true
			origCommit := commit

			fetchManifests.Go(func(ctx context.Context) (*cloudprovider.Publication, error) {
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

				return &cloudprovider.Publication{
					Cname:    flavor.Cname,
					Manifest: manifest,
					Target:   target,
				}, nil
			})
		}

		if !found {
			return fmt.Errorf("no publishing target for %s", flavor.Cname)
		}
	}
	err = fetchManifests.Wait()
	if err != nil {
		return fmt.Errorf("cannot fetch manifests: %w", err)
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

	for i, publication := range publications {
		lctx := log.WithValues(ctx, "cname", publication.Cname, "platform", publication.Target.Type())

		uptime := execTime(lctx)
		if uptime != 0 && uptime.Hours() > 5 {
			return errors.New("publishing taking too long, restart GLCI to resume")
		}

		var isPublished bool
		isPublished, err = publication.Target.IsPublished(publication.Manifest)
		if err != nil {
			return fmt.Errorf("cannot determine publishing status for %s: %w", publication.Cname, err)
		}
		if isPublished {
			log.Info(lctx, "Already published, skipping")
			continue
		}
		lctx = task.WithDomain(lctx, publication.Target.CanRollback())
		lctx = task.WithBatch(lctx, publication.Cname)
		lctx = task.WithUndeadMode(lctx, true)

		log.Info(lctx, "Publishing image")
		var output cloudprovider.PublishingOutput
		output, err = publication.Target.Publish(lctx, publication.Cname, publication.Manifest, sources)
		if err != nil {
			return fmt.Errorf("cannot publish %s to %s: %w", publication.Cname, publication.Target.Type(), err)
		}

		manifestOutput := publication.Manifest.PublishedImageMetadata
		manifestOutput, err = publications[i].Target.AddOwnPublishingOutput(manifestOutput, output)
		if err != nil {
			return fmt.Errorf("cannot add publishing output for %s: %w", publication.Cname, err)
		}
		publication.Manifest.PublishedImageMetadata = manifestOutput
		if glciVer != "" {
			publication.Manifest.GLCIVersion = glciVer
		}
		for _, j := range pubMap[publication.Cname] {
			publications[j].Manifest = publication.Manifest
		}

		log.Info(lctx, "Updating manifest")
		manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", publication.Cname, version, commit)
		task.RemoveCompleted(lctx, publication.Cname)
		err = cloudprovider.PutManifest(lctx, manifestTarget, manifestKey, publication.Manifest)
		if err != nil {
			return fmt.Errorf("cannot put manifest for %s: %w", publication.Cname, err)
		}
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

		ctx = log.WithValues(ctx, "ocmRepo", ocmTarget.OCMRepository())
		log.Info(ctx, "Publishing component descriptor")
		err = ocmTarget.PublishComponentDescriptor(ctx, version, descriptorYAML)
		if err != nil {
			return fmt.Errorf("cannot publish component descriptor: %w", err)
		}
	}

	log.Debug(ctx, "Closing sources and targets")
	err = closeSourcesAndTargetsAndPersistors(sources, targets, ocmTarget, state)
	if err != nil {
		return fmt.Errorf("cannot close sources and targets: %w", err)
	}

	log.Info(ctx, "Publishing completed successfully")
	return nil
}
