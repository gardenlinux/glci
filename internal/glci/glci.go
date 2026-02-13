package glci

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/task"
)

type (
	ctxkVer   struct{}
	ctxkStart struct{}
)

// WithVersion stores the GLCI version string into the context.
func WithVersion(ctx context.Context, version string) context.Context {
	return context.WithValue(ctx, ctxkVer{}, version)
}

// WithStart stores the GLCI start time into the context.
func WithStart(ctx context.Context, start time.Time) context.Context {
	return context.WithValue(ctx, ctxkStart{}, start)
}

func loadConfig(ctx context.Context, publishingConfig PublishingConfig) (credsprovider.CredsSource, cloudprovider.ArtifactSource,
	cloudprovider.ArtifactSource, map[string]cloudprovider.ArtifactSource, []cloudprovider.PublishingTarget, cloudprovider.OCMTarget,
	task.StatePersistor, error,
) {
	credsSource, err := credsprovider.NewCredsSource(publishingConfig.Credentials.Type)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid credentials source %s: %w", publishingConfig.Credentials.Type, err)
	}
	log.Info(ctx, "Configuring credentials source", "type", credsSource.Type())
	err = credsSource.SetCredsConfig(ctx, publishingConfig.Credentials.Config)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("cannot set credentials configuration for %s: %w",
			publishingConfig.Credentials.Type, err)
	}

	sources := make(map[string]cloudprovider.ArtifactSource, len(publishingConfig.Sources))
	configureSources := parallel.NewLimitedActivitySync(ctx, 3)
	for _, s := range publishingConfig.Sources {
		var source cloudprovider.ArtifactSource
		source, err = cloudprovider.NewArtifactSource(s.Type)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid artifact source %s: %w", s.ID, err)
		}
		configureSources.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			log.Info(ctx, "Configuring manifest source", "type", source.Type(), "id", s.ID)
			err = source.SetSourceConfig(ctx, credsSource, s.Config)
			if err != nil {
				return nil, fmt.Errorf("cannot set source configuration for %s: %w", s.ID, err)
			}

			return func() error {
				sources[s.ID] = source

				return nil
			}, nil
		})
	}
	err = configureSources.Wait()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}

	manifestSource := sources[publishingConfig.ManifestSource]
	manifestTarget := manifestSource
	if publishingConfig.ManifestTarget != "" {
		manifestTarget = sources[publishingConfig.ManifestTarget]
	}

	targets := make([]cloudprovider.PublishingTarget, 0, len(publishingConfig.Targets))
	rollbackHandlers := make(map[string]struct{}, len(publishingConfig.Targets))
	configureTargets := parallel.NewLimitedActivitySync(ctx, 3)
	for _, t := range publishingConfig.Targets {
		var target cloudprovider.PublishingTarget
		target, err = cloudprovider.NewPublishingTarget(t.Type)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid publishing target %s: %w", t.Type, err)
		}
		configureTargets.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			log.Info(ctx, "Configuring publishing target", "type", target.Type())
			err = target.SetTargetConfig(ctx, credsSource, t.Config, sources)
			if err != nil {
				return nil, fmt.Errorf("cannot set target configuration for %s: %w", t.Type, err)
			}
			domain := target.CanRollback()

			return func() error {
				_, ok := rollbackHandlers[domain]
				if ok {
					return fmt.Errorf("duplicate rollback handler %s for domain %s", t.Type, domain)
				}
				rollbackHandlers[domain] = struct{}{}

				targets = append(targets, target)

				return nil
			}, nil
		})
	}
	err = configureTargets.Wait()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}

	var ocmTarget cloudprovider.OCMTarget
	ocmTarget, err = cloudprovider.NewOCMTarget(publishingConfig.OCM.Type)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid OCM target %s: %w", publishingConfig.OCM.Type, err)
	}
	log.Info(ctx, "Configuring OCM target", "type", ocmTarget.Type())
	err = ocmTarget.SetOCMConfig(ctx, credsSource, publishingConfig.OCM.Config)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("cannot set target configuration for %s: %w", publishingConfig.OCM.Type, err)
	}

	var statePersistor task.StatePersistor
	statePersistor, err = task.NewStatePersistor(publishingConfig.State.Type)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid state persistor %s: %w", publishingConfig.State.Type, err)
	}
	log.Info(ctx, "Configuring state persistor", "type", statePersistor.Type())
	err = statePersistor.SetStateConfig(ctx, credsSource, publishingConfig.State.Config)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("cannot set state configuration for %s: %w", publishingConfig.State.Type, err)
	}

	return credsSource, manifestSource, manifestTarget, sources, targets, ocmTarget, statePersistor, nil
}

func closeSourcesAndTargetsAndPersistors(creds credsprovider.CredsSource, sources map[string]cloudprovider.ArtifactSource,
	targets []cloudprovider.PublishingTarget, ocmTarget cloudprovider.OCMTarget, state task.StatePersistor,
) error {
	errs := make([]error, 0, len(sources)+len(targets)+1)

	err := creds.Close()
	if err != nil {
		errs = append(errs, fmt.Errorf("cannot close credentials source: %w", err))
	}

	for _, source := range sources {
		err = source.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot close source %s: %w", source.Type(), err))
		}
	}

	for _, target := range targets {
		err = target.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot close target %s: %w", target.Type(), err))
		}
	}

	err = ocmTarget.Close()
	if err != nil {
		errs = append(errs, fmt.Errorf("cannot close OCM target %s: %w", ocmTarget.Type(), err))
	}

	err = state.Close()
	if err != nil {
		errs = append(errs, fmt.Errorf("cannot close state persistor %s: %w", state.Type(), err))
	}

	return errors.Join(errs...)
}

func glciVersion(ctx context.Context) string {
	ver, _ := ctx.Value(ctxkVer{}).(string)
	return ver
}

func execTime(ctx context.Context) time.Duration {
	start, ok := ctx.Value(ctxkStart{}).(time.Time)
	if !ok {
		return time.Duration(0)
	}
	return time.Since(start)
}

func id(version, commit string) string {
	return fmt.Sprintf("%s-%.8s", version, commit)
}
