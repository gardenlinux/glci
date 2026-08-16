package publisher

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	module.RegisterConfigType((*Publisher)(nil), &publisherConfig{})
}

// Publisher publishes Garden Linux releases.
type Publisher struct {
	base *module.Base

	creds          credsprovider.CredsSource
	sources        []cloudprovider.ArtifactSource
	manifestSource cloudprovider.ArtifactSource
	manifestTarget cloudprovider.ArtifactSource
	targets        []cloudprovider.PublishingTarget
	ocmTarget      cloudprovider.OCMTarget
	state          resilience.StatePersistor

	cfg     publisherConfig
	flavors []FlavorConfig
	aliases map[string][]string
}

// FlavorConfig is a Garden Linux release flavor together with its publishing configuration.
type FlavorConfig struct {
	Flavor                string `mapstructure:"flavor"`
	PublishingGroup       string `mapstructure:"publishing_group,omitzero"`
	CloudProfile          bool   `mapstructure:"cloud_profile,omitzero"`
	InComponentDescriptor bool   `mapstructure:"in_component_descriptor,omitzero"`
}

type publisherConfig struct {
	Credentials    module.Slot[credsprovider.CredsSource]           `mapstructure:"credentials"`
	Sources        module.SliceSlot[cloudprovider.ArtifactSource]   `mapstructure:"sources"`
	ManifestSource string                                           `mapstructure:"manifest_source"`
	ManifestTarget string                                           `mapstructure:"manifest_target,omitzero"`
	Targets        module.SliceSlot[cloudprovider.PublishingTarget] `mapstructure:"targets"`
	OCM            module.Slot[cloudprovider.OCMTarget]             `mapstructure:"ocm"`
	State          module.Slot[resilience.StatePersistor]           `mapstructure:"state"`
	Flavors        []FlavorConfig                                   `mapstructure:"flavors"`
	Aliases        map[string][]string                              `mapstructure:"aliases,omitempty"`
}

// NewPublisher creates a publisher.
func NewPublisher(b *module.Base) *Publisher {
	return &Publisher{
		base: b,
	}
}

// Configure recursively configures a publisher.
func (p *Publisher) Configure(rawCfg map[string]any) error {
	err := module.ParseConfig(rawCfg, &p.cfg)
	if err != nil {
		return err
	}

	p.flavors = p.cfg.Flavors
	p.aliases = p.cfg.Aliases

	if p.cfg.Credentials == nil {
		return errors.New("missing credentials")
	}
	p.creds, err = module.ConfigureModule(p.base, credsprovider.Category, p.cfg.Credentials)
	if err != nil {
		return fmt.Errorf("cannot configure credentials: %w", err)
	}

	if len(p.cfg.Sources.Items) == 0 {
		return errors.New("missing sources")
	}
	p.sources, err = module.ConfigureModules(p.base, cloudprovider.ArtifactSourceCategory, p.cfg.Sources)
	if err != nil {
		return fmt.Errorf("cannot configure sources: %w", err)
	}

	if len(p.cfg.Targets.Items) == 0 {
		return errors.New("missing targets")
	}
	p.targets, err = module.ConfigureModules(p.base, cloudprovider.PublishingTargetCategory, p.cfg.Targets)
	if err != nil {
		return fmt.Errorf("cannot configure targets: %w", err)
	}

	if p.cfg.OCM == nil {
		return errors.New("missing OCM")
	}
	p.ocmTarget, err = module.ConfigureModule(p.base, cloudprovider.OCMTargetCategory, p.cfg.OCM)
	if err != nil {
		return fmt.Errorf("cannot configure OCM: %w", err)
	}

	if p.cfg.State == nil {
		return errors.New("missing state")
	}
	p.state, err = module.ConfigureModule(p.base, resilience.Category, p.cfg.State)
	if err != nil {
		return fmt.Errorf("cannot configure state: %w", err)
	}

	if p.cfg.ManifestSource == "" {
		return errors.New("missing manifest source")
	}
	err = module.RegisterRef[cloudprovider.ArtifactSource](p.base, p, &p.manifestSource, p.cfg.ManifestSource)
	if err != nil {
		return fmt.Errorf("cannot register manifest source: %w", err)
	}

	manifestTargetID := p.cfg.ManifestTarget
	if manifestTargetID == "" {
		manifestTargetID = p.cfg.ManifestSource
	}
	err = module.RegisterRef[cloudprovider.ArtifactSource](p.base, p, &p.manifestTarget, manifestTargetID)
	if err != nil {
		return fmt.Errorf("cannot register manifest target: %w", err)
	}

	return nil
}

// Configurables returns configurable entities in support of the module system.
func (p *Publisher) Configurables() []module.Configurable {
	configurables := []module.Configurable{p.creds, p.ocmTarget, p.state}
	configurables = module.AppendConfigurables(configurables, p.sources)
	configurables = module.AppendConfigurables(configurables, p.targets)
	return configurables
}

func (p *Publisher) fetchManifests(ctx context.Context, version, commit string, steamroll bool) ([]publication, []groupPublication, string,
	error,
) {
	publications := make([]publication, len(p.flavors))
	fetchManifests := concurrency.NewActivitySync(ctx)
	for i, flavorConfig := range p.flavors {
		fetchManifests.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", flavorConfig.Flavor, version, commit)
			ctx = log.WithValues(ctx, "flavor", flavorConfig.Flavor)

			log.Debug(ctx, "Retrieving manifest")
			manifest, er := cloudprovider.GetManifest(ctx, p.manifestSource, manifestKey)
			if er != nil {
				return nil, fmt.Errorf("cannot get manifest for %s: %w", flavorConfig.Flavor, er)
			}
			if manifest.Version != version {
				return nil, fmt.Errorf("manifest for %s has incorrect version %s", flavorConfig.Flavor, manifest.Version)
			}
			if manifest.BuildCommittish != commit && fmt.Sprintf("%.8s", manifest.BuildCommittish) != commit {
				return nil, fmt.Errorf("manifest for %s has incorrect commit %s", flavorConfig.Flavor, manifest.BuildCommittish)
			}

			if p.manifestTarget != p.manifestSource {
				log.Debug(ctx, "Retrieving target manifest")
				var targetManifest *gardenlinux.Manifest
				targetManifest, er = cloudprovider.GetManifest(ctx, p.manifestTarget, manifestKey)
				_, ok := errors.AsType[*cloudprovider.KeyNotFoundError](er)
				if er != nil && !ok {
					return nil, fmt.Errorf("cannot get target manifest for %s: %w", flavorConfig.Flavor, er)
				}
				if targetManifest != nil {
					if targetManifest.Version != version {
						return nil, fmt.Errorf("target manifest for %s has incorrect version %s", flavorConfig.Flavor,
							targetManifest.Version)
					}
					if targetManifest.BuildCommittish != manifest.BuildCommittish {
						return nil, fmt.Errorf("target manifest for %s has incorrect commit %s", flavorConfig.Flavor,
							targetManifest.BuildCommittish)
					}

					manifest = targetManifest
				}
			}

			if manifest.PublishingGroup != "" && manifest.PublishingGroup != flavorConfig.PublishingGroup {
				return nil, fmt.Errorf("manifest for %s has publishing group %q conflicting with configured %q", flavorConfig.Flavor,
					manifest.PublishingGroup, flavorConfig.PublishingGroup)
			}

			publishingGroup := manifest.PublishingGroup
			if publishingGroup == "" {
				publishingGroup = flavorConfig.PublishingGroup
			}

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
					Target:                target,
					PublishingGroup:       publishingGroup,
					CloudProfile:          flavorConfig.CloudProfile,
					InComponentDescriptor: flavorConfig.InComponentDescriptor,
				}

				return nil
			}, nil
		})
	}
	err := fetchManifests.Wait()
	if err != nil {
		return nil, nil, "", err
	}

	if len(publications) != 0 {
		commit = publications[0].Manifest.BuildCommittish
		for i := range publications {
			if publications[i].Manifest.BuildCommittish != commit {
				return nil, nil, "", fmt.Errorf("manifests for %s and %s have a different commit", publications[0].Flavor,
					publications[i].Flavor)
			}
		}
	}

	groups := make(map[string][]*publication)
	for i := range publications {
		if publications[i].PublishingGroup == "" {
			continue
		}

		groups[publications[i].PublishingGroup] = append(groups[publications[i].PublishingGroup], &publications[i])
	}

	groupPublications := make([]groupPublication, 0, len(groups))
	fetchGroupManifests := concurrency.NewActivitySync(ctx)
	for group, pubs := range groups {
		fetchGroupManifests.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			target := pubs[0].Target
			for _, pub := range pubs {
				if pub.Target != target {
					return nil, fmt.Errorf("publishing group %s spans multiple targets", group)
				}
			}

			if !target.CanFuse() {
				return nil, fmt.Errorf("target %s for publishing group %s cannot fuse", target.Type(), group)
			}

			pub := groupPublication{
				Group:        group,
				Target:       target,
				publications: pubs,
			}
			ctx = log.WithValues(ctx, "group", group)

			log.Debug(ctx, "Retrieving group manifest")
			var er error
			pub.GroupManifest, er = cloudprovider.GetGroupManifest(ctx, p.manifestTarget, pub.manifestKey())
			_, ok := errors.AsType[*cloudprovider.KeyNotFoundError](er)
			if er != nil && !ok {
				return nil, fmt.Errorf("cannot get group manifest for %s: %w", group, er)
			}

			if pub.GroupManifest != nil && len(pub.GroupManifest.Manifests) != 0 {
				manifestKeys := make([]string, len(pub.publications))
				for i := range pub.publications {
					manifestKeys[i] = pub.publications[i].manifestKey()
				}
				if !equalSets(manifestKeys, pub.GroupManifest.Manifests) {
					return nil, fmt.Errorf("publishing group %s has incorrect members", group)
				}

				var fusedOutput cloudprovider.PublishingOutput
				for i := range pub.publications {
					output := pub.publications[i].Manifest.PublishedImageMetadata
					if output == nil {
						if !steamroll {
							return nil, fmt.Errorf("publishing group %s has unpublished member %s", group, pub.publications[i].Flavor)
						}

						continue
					}

					if fusedOutput == nil {
						fusedOutput = output
					} else if fmt.Sprint(fusedOutput) != fmt.Sprint(output) {
						return nil, fmt.Errorf("publishing group %s has divergent published metadata", group)
					}
				}
			}

			return func() error {
				groupPublications = append(groupPublications, pub)

				return nil
			}, nil
		})
	}
	err = fetchGroupManifests.Wait()
	if err != nil {
		return nil, nil, "", err
	}

	return publications, groupPublications, commit, nil
}

func (p *Publisher) selectTarget(manifest *gardenlinux.Manifest, flavor string) (cloudprovider.PublishingTarget, error) {
	var target cloudprovider.PublishingTarget
	for _, t := range p.targets {
		if !t.CanPublish(manifest) {
			continue
		}

		if target != nil {
			return nil, fmt.Errorf("multiple publishing targets for %s", flavor)
		}
		target = t
	}
	if target == nil {
		return nil, fmt.Errorf("no publishing target for %s", flavor)
	}

	return target, nil
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	seen := make(map[string]struct{}, len(a))
	for _, s := range a {
		seen[s] = struct{}{}
	}

	for _, s := range b {
		_, ok := seen[s]
		if !ok {
			return false
		}
	}

	return true
}

type publishingTask interface {
	isPublishingTask()
}

func (*Publisher) countFlavors(tasks []publishingTask) int {
	var count int
	for _, t := range tasks {
		_, ok := t.(*publication)
		if ok {
			count++
		}
	}

	return count
}

type groupPublication struct {
	Group         string
	GroupManifest *gardenlinux.GroupManifest

	Target       cloudprovider.PublishingTarget
	publications []*publication
}

func (*groupPublication) isPublishingTask() {}

func (p *groupPublication) manifestKey() string {
	return fmt.Sprintf("meta/singles/%s-%s-%.8s", p.Group, p.publications[0].Manifest.Version, p.publications[0].Manifest.BuildCommittish)
}

func (p *groupPublication) isPublished() bool {
	return p.GroupManifest != nil && len(p.GroupManifest.Manifests) != 0
}

type publication struct {
	gardenlinux.FlavorManifest

	Target                cloudprovider.PublishingTarget
	PublishingGroup       string
	CloudProfile          bool
	InComponentDescriptor bool
}

func (*publication) isPublishingTask() {}

func (p *publication) manifestKey() string {
	return fmt.Sprintf("meta/singles/%s-%s-%.8s", p.Flavor, p.Manifest.Version, p.Manifest.BuildCommittish)
}
