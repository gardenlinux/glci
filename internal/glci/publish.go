package glci

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ocm"
)

// Publish publishes a release to all cloud providers specified in the flavors and publishing configurations.
func Publish(ctx context.Context, flavorsConfig FlavorsConfig, publishingConfig PublishingConfig, aliasesConfig AliasesConfig,
	creds Credentials, version, commit string, omitComponentDescritpr bool,
) error {
	ctx = log.WithValues(ctx, "op", "publish", "version", version, "commit", commit)

	log.Debug(ctx, "Loading credentials and configuration")
	manifestSource, manifestTarget, sources, targets, ocmTarget, err := loadCredentialsAndConfig(ctx, creds, publishingConfig)
	if err != nil {
		return fmt.Errorf("invalid credentials or configuration: %w", err)
	}
	defer func() {
		_ = closeSourcesAndTargets(sources, targets, ocmTarget)
	}()

	glciVer := glciVersion(ctx)
	publications := make([]cloudprovider.Publication, 0, len(flavorsConfig.Flavors)*2)
	cdPublications := make([]cloudprovider.Publication, 0, len(flavorsConfig.Flavors))
	pubMap := make(map[string][]int, len(flavorsConfig.Flavors))
	for _, flavor := range flavorsConfig.Flavors {
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
			manifest, err = cloudprovider.GetManifest(lctx, manifestSource, manifestKey)
			if err != nil {
				return fmt.Errorf("cannot get manifest for %s: %w", flavor.Cname, err)
			}
			if manifest.Version != version {
				return fmt.Errorf("manifest for %s has incorrect version %s", flavor.Cname, manifest.Version)
			}
			if manifest.BuildCommittish != commit && fmt.Sprintf("%.8s", manifest.BuildCommittish) != commit {
				return fmt.Errorf("manifest for %s has incorrect commit %s", flavor.Cname, manifest.BuildCommittish)
			}
			commit = manifest.BuildCommittish

			if !target.CanPublish(manifest) {
				continue
			}

			log.Debug(lctx, "Retrieving target manifest")
			var targetManifest *gl.Manifest
			targetManifest, err = cloudprovider.GetManifest(lctx, manifestTarget, manifestKey)
			if err != nil && !errors.As(err, &cloudprovider.KeyNotFoundError{}) {
				return fmt.Errorf("cannot get target manifest for %s: %w", flavor.Cname, err)
			}
			if targetManifest != nil {
				if targetManifest.Version != version {
					return fmt.Errorf("target manifest for %s has incorrect version %s", flavor.Cname, targetManifest.Version)
				}
				if targetManifest.BuildCommittish != commit {
					return fmt.Errorf("target manifest for %s has incorrect commit %s", flavor.Cname, targetManifest.BuildCommittish)
				}

				if !target.CanPublish(targetManifest) {
					return errors.New("target manifest does not correspond to source manifest")
				}

				manifest = targetManifest
			}

			publication := cloudprovider.Publication{
				Cname:    flavor.Cname,
				Manifest: manifest,
				Target:   target,
			}
			publications = append(publications, publication)
			pubMap[flavor.Cname] = append(pubMap[flavor.Cname], len(publications)-1)
		}

		if !found {
			return fmt.Errorf("no publishing target for %s", flavor.Cname)
		}
	}
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
		err = cloudprovider.PutManifest(lctx, manifestTarget, manifestKey, publication.Manifest)
		if err != nil {
			return fmt.Errorf("cannot put manifest for %s: %w", publication.Cname, err)
		}
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

		log.Info(ctx, "Publishing component descriptor")
		err = ocmTarget.PublishComponentDescriptor(ctx, version, descriptorYAML)
		if err != nil {
			return fmt.Errorf("cannot publish component descriptor: %w", err)
		}
	}

	log.Debug(ctx, "Closing sources and targets")
	err = closeSourcesAndTargets(sources, targets, ocmTarget)
	if err != nil {
		return fmt.Errorf("cannot close sources and targets: %w", err)
	}

	log.Info(ctx, "Publishing completed successfully")
	return nil
}
