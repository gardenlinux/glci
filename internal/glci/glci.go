package glci

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gardenlinux/glci/internal/cloudprovider"
)

// WithVersion stores the GLCI version string into the context.
func WithVersion(ctx context.Context, version string) context.Context {
	return context.WithValue(ctx, ctxkVer{}, version)
}

// WithStart stores the GLCI start time into the context.
func WithStart(ctx context.Context, start time.Time) context.Context {
	return context.WithValue(ctx, ctxkStart{}, start)
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

type ctxkVer struct{}
type ctxkStart struct{}

func glciVersion(ctx context.Context) string {
	ver, _ := ctx.Value(ctxkVer{}).(string) //nolint:revive // An invalid or missing version results in an empty string.
	return ver
}

func execTime(ctx context.Context) time.Duration {
	start, ok := ctx.Value(ctxkStart{}).(time.Time)
	if !ok {
		return time.Duration(0)
	}
	return time.Since(start)
}
