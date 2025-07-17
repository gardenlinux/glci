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
	creds Credentials, version, commit string,
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

	publications := make([]cloudprovider.Publication, 0, len(flavorsConfig.Flavors))
	for _, flavor := range flavorsConfig.Flavors {
		for _, target := range targets {
			if target.Type() != flavor.Platform {
				continue
			}
			lctx := log.WithValues(ctx, "cname", flavor.Cname, "platform", flavor.Platform)

			log.Info(lctx, "Retrieving manifest")
			var manifest *gl.Manifest
			manifest, err = manifestSource.GetManifest(lctx, fmt.Sprintf("meta/singles/%s-%s-%.8s", flavor.Cname, version, commit))
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

			log.Debug(lctx, "Retrieving target manifest")
			var targetManifest *gl.Manifest
			targetManifest, err = manifestTarget.GetManifest(lctx, fmt.Sprintf("meta/singles/%s-%s-%.8s", flavor.Cname, version, commit))
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

				if targetManifest.PublishedImageMetadata != nil {
					log.Info(lctx, "Already published, skipping")
					continue
				}
			}

			publications = append(publications, cloudprovider.Publication{
				Cname:    flavor.Cname,
				Manifest: manifest,
				Target:   target,
			})
		}
	}

	var descriptor *ocm.ComponentDescriptor
	descriptor, err = ocm.BuildComponentDescriptor(ctx, manifestSource, publications, ocmTarget, aliasesConfig, version, commit)
	if err != nil {
		return fmt.Errorf("cannot build component descriptor: %w", err)
	}

	log.Info(ctx, "Publishing images", "count", len(publications))
	for i, publication := range publications {
		lctx := log.WithValues(ctx, "cname", publication.Cname, "platform", publication.Target.Type())

		log.Info(lctx, "Publishing image")
		var output cloudprovider.PublishingOutput
		output, err = publication.Target.Publish(lctx, publication.Cname, publication.Manifest, sources)
		if err != nil {
			return fmt.Errorf("cannot publish %s to %s: %w", publication.Cname, publication.Target.Type(), err)
		}
		publications[i].Manifest.PublishedImageMetadata = output

		log.Info(lctx, "Updating manifest")
		err = manifestTarget.PutManifest(lctx, fmt.Sprintf("meta/singles/%s-%s-%.8s", publication.Cname, version, commit),
			publication.Manifest)
		if err != nil {
			return fmt.Errorf("cannot put manifest for %s: %w", publication.Cname, err)
		}
	}

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

	log.Info(ctx, "Publishing component descriptor")
	err = ocmTarget.PublishComponentDescriptor(ctx, version, descriptorYAML)
	if err != nil {
		return fmt.Errorf("cannot publish component descriptor: %w", err)
	}

	log.Debug(ctx, "Closing sources and targets")
	err = closeSourcesAndTargets(sources, targets, ocmTarget)
	if err != nil {
		return fmt.Errorf("cannot close sources and targets: %w", err)
	}

	log.Info(ctx, "Publishing completed successfully")
	return nil
}

// Remove removes a release from all cloud providers specified in the flavors and publishing configurations.
func Remove(ctx context.Context, flavorsConfig FlavorsConfig, publishingConfig PublishingConfig, creds Credentials, version,
	commit string,
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

	publications := make([]cloudprovider.Publication, 0, len(flavorsConfig.Flavors))
	for _, flavor := range flavorsConfig.Flavors {
		for _, target := range targets {
			if target.Type() != flavor.Platform {
				continue
			}
			lctx := log.WithValues(ctx, "cname", flavor.Cname, "platform", flavor.Platform)

			log.Info(lctx, "Retrieving manifest")
			var manifest *gl.Manifest
			manifest, err = manifestTarget.GetManifest(lctx, fmt.Sprintf("meta/singles/%s-%s-%.8s", flavor.Cname, version, commit))
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

			if manifest.PublishedImageMetadata == nil {
				log.Debug(lctx, "Already removed, skipping")
				continue
			}

			publications = append(publications, cloudprovider.Publication{
				Cname:    flavor.Cname,
				Manifest: manifest,
				Target:   target,
			})
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
		err = publication.Target.Remove(lctx, publication.Cname, publication.Manifest, sources)
		if err != nil {
			return fmt.Errorf("cannot remove %s from %s: %w", publication.Cname, publication.Target.Type(), err)
		}
		publications[i].Manifest.PublishedImageMetadata = nil

		log.Info(lctx, "Updating manifest")
		err = manifestTarget.PutManifest(lctx, fmt.Sprintf("meta/singles/%s-%s-%.8s", publication.Cname, version, commit),
			publication.Manifest)
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

func loadCredentialsAndConfig(ctx context.Context, creds Credentials, publishingConfig PublishingConfig) (cloudprovider.ArtifactSource,
	cloudprovider.ArtifactSource, map[string]cloudprovider.ArtifactSource, []cloudprovider.PublishingTarget, cloudprovider.OCMTarget,
	error,
) {
	sources := make(map[string]cloudprovider.ArtifactSource, len(publishingConfig.Sources))
	for _, s := range publishingConfig.Sources {
		source, err := cloudprovider.NewArtifactSource(s.Type)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid artifact source %s: %w", s.ID, err)
		}
		err = source.SetCredentials(creds)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("cannot set credentials for %s: %w", s.ID, err)
		}
		err = source.SetSourceConfig(ctx, s.Config)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("cannot set source configuration for %s: %w", s.ID, err)
		}
		sources[s.ID] = source
	}

	manifestSource := sources[publishingConfig.ManifestSource]
	manifestTarget := manifestSource
	if publishingConfig.ManifestTarget != nil {
		manifestTarget = sources[*publishingConfig.ManifestTarget]
	}

	targets := make([]cloudprovider.PublishingTarget, 0, len(publishingConfig.Targets))
	for _, t := range publishingConfig.Targets {
		target, err := cloudprovider.NewPublishingTarget(t.Type)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid publishing target %s: %w", t.Type, err)
		}
		err = target.SetCredentials(creds)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("cannot set credentials for %s: %w", t.Type, err)
		}
		err = target.SetTargetConfig(ctx, t.Config, sources)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("cannot set source configuration for %s: %w", t.Type, err)
		}
		targets = append(targets, target)
	}

	ocmTarget, err := cloudprovider.NewOCMTarget(publishingConfig.OCM.Type)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("invalid OCM target %s: %w", publishingConfig.OCM.Type, err)
	}
	err = ocmTarget.SetCredentials(creds)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("cannot set credentials for %s: %w", publishingConfig.OCM.Type, err)
	}
	err = ocmTarget.SetOCMConfig(ctx, publishingConfig.OCM.Config)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("cannot set target configuration for %s: %w", publishingConfig.OCM.Type, err)
	}

	return manifestSource, manifestTarget, sources, targets, ocmTarget, nil
}

func closeSourcesAndTargets(sources map[string]cloudprovider.ArtifactSource, targets []cloudprovider.PublishingTarget,
	ocmTarget cloudprovider.OCMTarget,
) error {
	errs := make([]error, 0, len(sources)+len(targets)+1)

	for _, source := range sources {
		err := source.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot close source %s: %w", source.Type(), err))
		}
	}

	for _, target := range targets {
		err := target.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot close target %s: %w", target.Type(), err))
		}
	}

	err := ocmTarget.Close()
	if err != nil {
		errs = append(errs, fmt.Errorf("cannot close OCM target %s: %w", ocmTarget.Type(), err))
	}

	return errors.Join(errs...)
}
