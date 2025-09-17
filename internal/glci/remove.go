package glci

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
)

// Remove removes a release from all cloud providers specified in the flavors and publishing configurations.
func Remove(ctx context.Context, flavorsConfig FlavorsConfig, publishingConfig PublishingConfig, creds Credentials, version, commit string,
) error {
	ctx = log.WithValues(ctx, "op", "remove", "version", version, "commit", commit)

	log.Debug(ctx, "Loading credentials and configuration")
	manifestSource, manifestTarget, sources, targets, ocmTarget, err := loadCredentialsAndConfig(ctx, creds, publishingConfig)
	if err != nil {
		return fmt.Errorf("invalid credentials or configuration: %w", err)
	}
	defer func() {
		_ = closeSourcesAndTargets(sources, targets, ocmTarget)
	}()

	publications := make([]cloudprovider.Publication, 0, len(flavorsConfig.Flavors)*2)
	pubMap := make(map[string][]int, len(flavorsConfig.Flavors))
	for _, flavor := range flavorsConfig.Flavors {
		flavorPubs := pubMap[flavor.Cname]
		found := false

		for _, target := range targets {
			if target.Type() != flavor.Platform {
				continue
			}
			found = true
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", flavor.Cname, version, commit)
			lctx := log.WithValues(ctx, "cname", flavor.Cname, "platform", flavor.Platform)

			log.Info(lctx, "Retrieving manifest")
			var manifest *gl.Manifest
			manifest, err = cloudprovider.GetManifest(lctx, manifestTarget, manifestKey)
			if err != nil {
				if errors.As(err, &cloudprovider.KeyNotFoundError{}) && manifestTarget != manifestSource {
					log.Debug(lctx, "Manifest not found, skipping")
					continue
				}
				return fmt.Errorf("cannot get manifest for %s: %w", flavor.Cname, err)
			}
			if manifest.Version != version {
				return fmt.Errorf("manifest for %s has incorrect version %s", flavor.Cname, manifest.Version)
			}
			if manifest.BuildCommittish != commit && fmt.Sprintf("%.8s", manifest.BuildCommittish) != commit {
				return fmt.Errorf("manifest for %s has incorrect commit %s", flavor.Cname, manifest.BuildCommittish)
			}
			commit = manifest.BuildCommittish

			if target.CanPublish(manifest) {
				continue
			}

			var isPublished bool
			isPublished, err = target.IsPublished(manifest)
			if err != nil {
				return fmt.Errorf("cannot determine publishing status for %s: %w", flavor.Cname, err)
			}
			if !isPublished {
				log.Debug(lctx, "Already removed, skipping")
				continue
			}

			publications = append(publications, cloudprovider.Publication{
				Cname:    flavor.Cname,
				Manifest: manifest,
				Target:   target,
			})
			pubMap[flavor.Cname] = append(flavorPubs, len(publications)-1)
		}
		if !found {
			return fmt.Errorf("no publishing target for %s", flavor.Cname)
		}
	}

	if len(publications) > 0 {
		log.Info(ctx, "Removing images", "count", len(publications))
	} else {
		log.Info(ctx, "Nothing to remove")
	}

	for i, publication := range publications {
		lctx := log.WithValues(ctx, "cname", publication.Cname, "platform", publication.Target.Type())

		log.Info(lctx, "Removing image")
		err = publication.Target.Remove(lctx, publication.Manifest, sources)
		if err != nil {
			return fmt.Errorf("cannot remove %s from %s: %w", publication.Cname, publication.Target.Type(), err)
		}

		manifestOutput := publication.Manifest.PublishedImageMetadata
		manifestOutput, err = publications[i].Target.RemoveOwnPublishingOutput(manifestOutput)
		if err != nil {
			return fmt.Errorf("cannot remove publishing output for %s: %w", publication.Cname, err)
		}
		publication.Manifest.PublishedImageMetadata = manifestOutput
		glciVer := glciVersion(ctx)
		if glciVer != "" {
			publication.Manifest.GLCIVersion = &glciVer
		}

		log.Info(lctx, "Updating manifest")
		manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", publication.Cname, version, commit)
		err = cloudprovider.PutManifest(lctx, manifestTarget, manifestKey, publication.Manifest)
		if err != nil {
			return fmt.Errorf("cannot put manifest for %s: %w", publication.Cname, err)
		}
	}

	log.Debug(ctx, "Closing sources and targets")
	err = closeSourcesAndTargets(sources, targets, ocmTarget)
	if err != nil {
		return fmt.Errorf("cannot close sources and targets: %w", err)
	}

	log.Info(ctx, "Removing completed successfully")
	return nil
}
