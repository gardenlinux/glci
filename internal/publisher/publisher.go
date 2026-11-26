package publisher

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/gardenlinux/glci/internal/cli"
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
	Flavor       string   `mapstructure:"flavor"`
	Destinations []string `mapstructure:"destinations,omitempty"`
}

type publisherConfig struct {
	Credentials    module.Slot[credsprovider.CredsSource]           `mapstructure:"credentials"`
	Sources        module.SliceSlot[cloudprovider.ArtifactSource]   `mapstructure:"sources"`
	ManifestSource string                                           `mapstructure:"manifest_source"`
	ManifestTarget string                                           `mapstructure:"manifest_target,omitzero"`
	Targets        module.SliceSlot[cloudprovider.PublishingTarget] `mapstructure:"targets"`
	OCM            ocmConfig                                        `mapstructure:"ocm"`
	State          module.Slot[resilience.StatePersistor]           `mapstructure:"state"`
	Flavors        []FlavorConfig                                   `mapstructure:"flavors"`
	Aliases        map[string][]string                              `mapstructure:"aliases,omitempty"`
}

type ocmConfig struct {
	ProjectRepository string            `mapstructure:"project_repository"`
	Provider          string            `mapstructure:"provider"`
	Responsibles      []string          `mapstructure:"responsibles,omitempty"`
	Flavors           []ocmFlavorConfig `mapstructure:"flavors,omitempty"`
	//nolint:revive,nolintlint // The remain tag overrides the -, which is necessary to avoid an implicit name.
	Target module.Slot[cloudprovider.OCMTarget] `mapstructure:"-,remain"`
}

type ocmFlavorConfig struct {
	Flavor       string   `mapstructure:"flavor"`
	Destinations []string `mapstructure:"destinations,omitempty"`
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
	p.creds, err = p.base.ConfigureModule(credsprovider.Category, p.cfg.Credentials)
	if err != nil {
		return fmt.Errorf("cannot configure credentials: %w", err)
	}

	if len(p.cfg.Sources.Items) == 0 {
		return errors.New("missing sources")
	}
	p.sources, err = p.base.ConfigureModules(cloudprovider.ArtifactSourceCategory, p.cfg.Sources)
	if err != nil {
		return fmt.Errorf("cannot configure sources: %w", err)
	}

	if len(p.cfg.Targets.Items) == 0 {
		return errors.New("missing targets")
	}
	p.targets, err = p.base.ConfigureModules(cloudprovider.PublishingTargetCategory, p.cfg.Targets)
	if err != nil {
		return fmt.Errorf("cannot configure targets: %w", err)
	}

	if p.cfg.OCM.ProjectRepository == "" {
		return errors.New("missing OCM project repository")
	}
	if p.cfg.OCM.Provider == "" {
		return errors.New("missing OCM provider")
	}
	if p.cfg.OCM.Target == nil {
		return errors.New("missing OCM")
	}
	p.ocmTarget, err = p.base.ConfigureModule(cloudprovider.OCMTargetCategory, p.cfg.OCM.Target)
	if err != nil {
		return fmt.Errorf("cannot configure OCM: %w", err)
	}

	if p.cfg.State == nil {
		return errors.New("missing state")
	}
	p.state, err = p.base.ConfigureModule(resilience.Category, p.cfg.State)
	if err != nil {
		return fmt.Errorf("cannot configure state: %w", err)
	}

	if p.cfg.ManifestSource == "" {
		return errors.New("missing manifest source")
	}
	err = p.base.RegisterRef[cloudprovider.ArtifactSource](p, &p.manifestSource, p.cfg.ManifestSource)
	if err != nil {
		return fmt.Errorf("cannot register manifest source: %w", err)
	}

	manifestTargetID := p.cfg.ManifestTarget
	if manifestTargetID == "" {
		manifestTargetID = p.cfg.ManifestSource
	}
	err = p.base.RegisterRef[cloudprovider.ArtifactSource](p, &p.manifestTarget, manifestTargetID)
	if err != nil {
		return fmt.Errorf("cannot register manifest target: %w", err)
	}

	flavors := make(map[string]struct{}, len(p.flavors))
	for _, flavorConfig := range p.flavors {
		_, ok := flavors[flavorConfig.Flavor]
		if ok {
			return fmt.Errorf("duplicate flavor %q", flavorConfig.Flavor)
		}
		flavors[flavorConfig.Flavor] = struct{}{}
	}

	publishingGroupOwners := make(map[string]cloudprovider.PublishingTarget)
	resourceOwners := make(map[string]cloudprovider.PublishingTarget)
	targetDestinationKeys := make(map[string][]string)
	for _, t := range p.targets {
		for _, resource := range t.Resources() {
			owner, ok := resourceOwners[resource]
			if ok && owner != t {
				return fmt.Errorf("duplicate resource %q", resource)
			}
			resourceOwners[resource] = t
		}

		targetDestinationKeys[t.Type()] = t.DestinationKeys()

		for _, groupCfg := range t.PublishingGroupConfigs() {
			owner, ok := publishingGroupOwners[groupCfg.PublishingGroup]
			if ok && owner != t {
				return fmt.Errorf("duplicate publishing group %q", groupCfg.PublishingGroup)
			}
			publishingGroupOwners[groupCfg.PublishingGroup] = t

			for _, f := range groupCfg.Flavors {
				_, ok = flavors[f]
				if !ok {
					return fmt.Errorf("unknown flavor %q in publishing group %q", f, groupCfg.PublishingGroup)
				}
			}
		}
	}

	seen := make(map[string]struct{}, len(p.cfg.OCM.Flavors))
	for _, flavorCfg := range p.cfg.OCM.Flavors {
		_, ok := flavors[flavorCfg.Flavor]
		if !ok {
			return fmt.Errorf("unknown flavor %q in component descriptor", flavorCfg.Flavor)
		}

		_, ok = seen[flavorCfg.Flavor]
		if ok {
			return fmt.Errorf("duplicate flavor %q in component descriptor", flavorCfg.Flavor)
		}
		seen[flavorCfg.Flavor] = struct{}{}

		err = p.validateDestinations(flavorCfg.Destinations, targetDestinationKeys)
		if err != nil {
			return fmt.Errorf("cannot validate destinations in component descriptor: %w", err)
		}
	}

	for _, flavorCfg := range p.flavors {
		err = p.validateDestinations(flavorCfg.Destinations, targetDestinationKeys)
		if err != nil {
			return fmt.Errorf("cannot validate destinations in flavor %q: %w", flavorCfg.Flavor, err)
		}
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

// SourceConfigurables returns its configurables that are artifact sources.
func (p *Publisher) SourceConfigurables() []module.Configurable {
	return module.AppendConfigurables(nil, p.sources)
}

func (p *Publisher) assembleFlavors(ctx context.Context, version, commit string) ([]*flavor, []groupPublication, string,
	error,
) {
	flavors := make([]*flavor, len(p.flavors))
	fetchManifests := concurrency.NewActivity(ctx)
	for i, flavorConfig := range p.flavors {
		fetchManifests.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "flavor", flavorConfig.Flavor)

			manifest, inErr := p.fetchManifest(ctx, flavorConfig, version, commit)
			if inErr != nil {
				return inErr
			}

			var destinations []destination
			destinations, inErr = p.selectDestinations(manifest, flavorConfig.Destinations)
			if inErr != nil {
				return inErr
			}

			f := &flavor{
				manifest:     manifest,
				publications: make([]publication, len(destinations)),
			}
			for j, dest := range destinations {
				var reversible bool
				reversible, inErr = dest.target.Reversible(manifest, dest.key)
				if inErr != nil {
					return fmt.Errorf("cannot determine reversibility for %s: %w", manifest.Flavor, inErr)
				}

				f.publications[j] = publication{
					flavor:         f,
					target:         dest.target,
					destinationKey: dest.key,
					reversible:     reversible,
				}
			}
			flavors[i] = f

			return nil
		})
	}
	err := fetchManifests.Wait()
	if err != nil {
		return nil, nil, "", err
	}

	if len(flavors) != 0 {
		commit = flavors[0].manifest.BuildCommittish
		for _, f := range flavors {
			if f.manifest.BuildCommittish != commit {
				return nil, nil, "", fmt.Errorf("manifests for %s and %s have a different commit", flavors[0].manifest.Flavor,
					f.manifest.Flavor)
			}
		}
	}

	type groupPublicationKey struct {
		target          cloudprovider.PublishingTarget
		publishingGroup string
	}

	var groupPublications []groupPublication
	groupPublicationIndex := make(map[groupPublicationKey]int)
	for _, f := range flavors {
		for i := range f.publications {
			pub := f.publications[i]
			if !pub.target.CanFuse() {
				continue
			}

			key := groupPublicationKey{
				target:          pub.target,
				publishingGroup: pub.publishingGroup(),
			}
			j, ok := groupPublicationIndex[key]
			if !ok {
				j = len(groupPublications)
				groupPublicationIndex[key] = j

				groupPublications = append(groupPublications, groupPublication{
					group:  key.publishingGroup,
					target: key.target,
				})
			}
			groupPublications[j].publications = append(groupPublications[j].publications, pub)
		}
	}

	for i := range groupPublications {
		groupPub := &groupPublications[i]
		groupPub.manifests = make([]*gardenlinux.Manifest, 0, len(groupPub.publications))
		groupPub.manifestKeys = make([]string, 0, len(groupPub.publications))
		flavorsSeen := make(map[*flavor]struct{}, len(groupPub.publications))

		for j := range groupPub.publications {
			pub := groupPub.publications[j]

			_, ok := flavorsSeen[pub.flavor]
			if !ok {
				flavorsSeen[pub.flavor] = struct{}{}
				groupPub.manifests = append(groupPub.manifests, pub.flavor.manifest)
				groupPub.manifestKeys = append(groupPub.manifestKeys, pub.manifestKey())
			}
		}
	}

	fetchGroupManifests := concurrency.NewActivity(ctx)
	for i := range groupPublications {
		fetchGroupManifests.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "publishingGroup", groupPublications[i].group)

			log.Debug(ctx, "Retrieving group manifest")
			groupManifest, inErr := cloudprovider.GetGroupManifest(ctx, p.manifestTarget, groupPublications[i].manifestKey())
			_, ok := errors.AsType[*cloudprovider.KeyNotFoundError](inErr)
			if inErr != nil && !ok {
				return fmt.Errorf("cannot get group manifest for %s: %w", groupPublications[i].group, inErr)
			}

			groupPublications[i].groupManifest = groupManifest

			return nil
		})
	}
	err = fetchGroupManifests.Wait()
	if err != nil {
		return nil, nil, "", err
	}

	return flavors, groupPublications, commit, nil
}

func (p *Publisher) fetchManifest(ctx context.Context, flavorConfig FlavorConfig, version, commit string) (*gardenlinux.Manifest, error) {
	manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", flavorConfig.Flavor, version, commit)

	log.Debug(ctx, "Retrieving manifest")
	manifest, err := cloudprovider.GetManifest(ctx, p.manifestSource, manifestKey)
	if err != nil {
		return nil, fmt.Errorf("cannot get manifest for %s: %w", flavorConfig.Flavor, err)
	}
	if manifest.Version != version {
		return nil, fmt.Errorf("manifest for %s has incorrect version %s", flavorConfig.Flavor, manifest.Version)
	}
	if manifest.BuildCommittish != commit && fmt.Sprintf("%.8s", manifest.BuildCommittish) != commit {
		return nil, fmt.Errorf("manifest for %s has incorrect commit %s", flavorConfig.Flavor, manifest.BuildCommittish)
	}
	if manifest.Flavor != "" && manifest.Flavor != flavorConfig.Flavor {
		return nil, fmt.Errorf("manifest for %s has incorrect flavor %s", flavorConfig.Flavor, manifest.Flavor)
	}

	if p.manifestTarget != p.manifestSource {
		log.Debug(ctx, "Retrieving target manifest")

		var targetManifest *gardenlinux.Manifest
		targetManifest, err = cloudprovider.GetManifest(ctx, p.manifestTarget, manifestKey)
		_, ok := errors.AsType[*cloudprovider.KeyNotFoundError](err)
		if err != nil && !ok {
			return nil, fmt.Errorf("cannot get target manifest for %s: %w", flavorConfig.Flavor, err)
		}

		if targetManifest != nil {
			if targetManifest.Version != version {
				return nil, fmt.Errorf("target manifest for %s has incorrect version %s", flavorConfig.Flavor, targetManifest.Version)
			}
			if targetManifest.BuildCommittish != manifest.BuildCommittish {
				return nil, fmt.Errorf("target manifest for %s has incorrect commit %s", flavorConfig.Flavor,
					targetManifest.BuildCommittish)
			}
			if targetManifest.Flavor != "" && targetManifest.Flavor != flavorConfig.Flavor {
				return nil, fmt.Errorf("target manifest for %s has incorrect flavor %s", flavorConfig.Flavor, targetManifest.Flavor)
			}

			manifest = targetManifest
		}
	}

	manifest.Flavor = flavorConfig.Flavor
	manifest.GLCIVersion = cli.Version(ctx)

	return manifest, nil
}

type destination struct {
	target cloudprovider.PublishingTarget
	key    string
}

func (p *Publisher) selectDestinations(manifest *gardenlinux.Manifest, configuredDestinations []string) ([]destination, error) {
	var destinations []destination
	for _, t := range p.targets {
		for _, d := range t.Destinations(manifest) {
			destinations = append(destinations, destination{
				target: t,
				key:    d.Key,
			})
		}
	}
	if len(destinations) == 0 {
		return nil, fmt.Errorf("no destination configured for %q", manifest.Flavor)
	}

	if len(configuredDestinations) == 0 {
		return destinations, nil
	}

	var selectedDestinations []destination
	for _, d := range configuredDestinations {
		var found bool
		for _, dest := range destinations {
			candidate := cloudprovider.Destination{
				Target: dest.target.Type(),
				Key:    dest.key,
			}
			if p.destinationMatches(candidate, d) {
				selectedDestinations = append(selectedDestinations, dest)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("flavor %q not published to destination %q", manifest.Flavor, d)
		}
	}

	return selectedDestinations, nil
}

func (*Publisher) destinationMatches(destination cloudprovider.Destination, dest string) bool {
	target, key, ok := strings.Cut(dest, "/")

	return destination.Target == target && (!ok || destination.Key == key)
}

func (*Publisher) validateDestinations(configuredDestinations []string, targetDestinationKeys map[string][]string) error {
	seen := make(map[string]struct{})
	for _, dest := range configuredDestinations {
		target, destinationKey, keyed := strings.Cut(dest, "/")

		destinationKeys, ok := targetDestinationKeys[target]
		if !ok {
			return fmt.Errorf("unknown target %q", target)
		}

		var destinations []string
		if keyed {
			if destinationKey != strings.ToLower(destinationKey) || strings.Contains(destinationKey, ".") {
				return fmt.Errorf("invalid destination %q: key must be lowercase and contain no '.'", dest)
			}
			if !slices.Contains(destinationKeys, destinationKey) {
				return fmt.Errorf("unknown destination %q", dest)
			}
			destinations = []string{dest}
		} else {
			for _, key := range destinationKeys {
				destinations = append(destinations, cloudprovider.Destination{
					Target: target,
					Key:    key,
				}.String())
			}
		}

		for _, d := range destinations {
			_, ok = seen[d]
			if ok {
				return fmt.Errorf("duplicate destination %q", d)
			}
			seen[d] = struct{}{}
		}
	}

	return nil
}

func (p *Publisher) validatePreconditions(flavors []*flavor, groupPublications []groupPublication, allowUnpublishedGroupMembers bool,
) error {
	err := p.validateManifestPublishingGroups(flavors)
	if err != nil {
		return fmt.Errorf("invalid manifest publishing groups: %w", err)
	}

	err = p.validatePublishedFlavors(flavors)
	if err != nil {
		return fmt.Errorf("invalid published flavors: %w", err)
	}

	err = p.validatePublishedGroups(groupPublications, allowUnpublishedGroupMembers)
	if err != nil {
		return fmt.Errorf("invalid published groups: %w", err)
	}

	return nil
}

func (p *Publisher) validateManifestPublishingGroups(flavors []*flavor) error {
	groups := make(map[string]struct{})
	groupsFromConfig := make(map[string]struct{})
	for _, t := range p.targets {
		for _, groupCfg := range t.PublishingGroupConfigs() {
			groups[groupCfg.PublishingGroup] = struct{}{}
			if len(groupCfg.Flavors) != 0 {
				groupsFromConfig[groupCfg.PublishingGroup] = struct{}{}
			}
		}
	}

	for _, f := range flavors {
		group := f.manifest.PublishingGroup
		if group == "" {
			continue
		}

		_, ok := groups[group]
		if !ok {
			return fmt.Errorf("publishing group %q has no destination", group)
		}

		_, ok = groupsFromConfig[group]
		if ok {
			return fmt.Errorf("publishing group %q configured and also named in a manifest", group)
		}
	}

	return nil
}

func (*Publisher) validatePublishedFlavors(flavors []*flavor) error {
	for _, f := range flavors {
		destinations := make(map[string]struct{})
		for i := range f.publications {
			destinations[f.publications[i].destination().String()] = struct{}{}
		}

		for dest := range f.manifest.PublishedImageMetadata {
			_, ok := destinations[dest]
			if !ok {
				return fmt.Errorf("unknown destination %q in published image metadata for %s", dest, f.manifest.Flavor)
			}
		}
		for dest := range f.manifest.IndividualPublishedImageMetadata {
			_, ok := destinations[dest]
			if !ok {
				return fmt.Errorf("unknown destination %q in individual published image metadata for %s", dest, f.manifest.Flavor)
			}
		}
	}

	return nil
}

func (*Publisher) validatePublishedGroups(groupPublications []groupPublication, allowUnpublishedGroupMembers bool) error {
	for i := range groupPublications {
		groupPub := groupPublications[i]
		if !groupPub.isPublished() {
			continue
		}

		if !equalSets(groupPub.manifestKeys, groupPub.groupManifest.Manifests) {
			return fmt.Errorf("publishing group %q does not match its published record", groupPub.group)
		}

		outputs := make(map[string]any)
		for j := range groupPub.publications {
			pub := groupPub.publications[j]

			output := pub.flavor.manifest.PublishedImageMetadata[pub.destination().String()]
			if output == nil {
				if allowUnpublishedGroupMembers {
					continue
				}

				return fmt.Errorf("publishing group %q has unpublished member %q", groupPub.group, pub.flavor.manifest.Flavor)
			}

			expectedOutput, ok := outputs[pub.destinationKey]
			switch {
			case !ok:
				outputs[pub.destinationKey] = output
			case fmt.Sprint(expectedOutput) != fmt.Sprint(output):
				return fmt.Errorf("publishing group %q has inconsistent published metadata", groupPub.group)
			}
		}
	}

	return nil
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
		_, ok := t.(publication)
		if ok {
			count++
		}
	}

	return count
}

func (p *Publisher) gatherReplications(ctx context.Context, version, commit string) ([]cloudprovider.Replication, error) {
	requiredReplications := make([][]cloudprovider.Replication, len(p.flavors))
	gatherReplications := concurrency.NewActivity(ctx)
	for i, flavorConfig := range p.flavors {
		gatherReplications.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "flavor", flavorConfig.Flavor)

			manifest, inErr := p.fetchManifest(ctx, flavorConfig, version, commit)
			if inErr != nil {
				return inErr
			}

			var replications []cloudprovider.Replication
			for _, t := range p.targets {
				var targetReplications []cloudprovider.Replication
				targetReplications, inErr = t.RequiredReplications(manifest)
				if inErr != nil {
					return fmt.Errorf("cannot determine replications for %s: %w", flavorConfig.Flavor, inErr)
				}

				replications = append(replications, targetReplications...)
			}
			requiredReplications[i] = replications

			return nil
		})
	}
	err := gatherReplications.Wait()
	if err != nil {
		return nil, err
	}

	var replications []cloudprovider.Replication
	seen := make(map[cloudprovider.Replication]struct{})
	for _, flavorReplications := range requiredReplications {
		for _, replication := range flavorReplications {
			_, ok := seen[replication]
			if ok {
				continue
			}
			seen[replication] = struct{}{}

			replications = append(replications, replication)
		}
	}

	return replications, nil
}

type groupPublication struct {
	group  string
	target cloudprovider.PublishingTarget

	publications []publication
	manifests    []*gardenlinux.Manifest
	manifestKeys []string

	groupManifest *gardenlinux.GroupManifest
}

func (*groupPublication) isPublishingTask() {}

func (p *groupPublication) manifestKey() string {
	return fmt.Sprintf("meta/singles/%s-%s-%.8s", p.group, p.publications[0].flavor.manifest.Version,
		p.publications[0].flavor.manifest.BuildCommittish)
}

func (p *groupPublication) isPublished() bool {
	return p.groupManifest != nil && len(p.groupManifest.Manifests) != 0
}

type flavor struct {
	manifestMtx sync.Mutex
	manifest    *gardenlinux.Manifest

	publications []publication
}

type publication struct {
	flavor *flavor

	target         cloudprovider.PublishingTarget
	destinationKey string
	reversible     bool
}

func (publication) isPublishingTask() {}

func (p publication) manifestKey() string {
	return fmt.Sprintf("meta/singles/%s-%s-%.8s", p.flavor.manifest.Flavor, p.flavor.manifest.Version, p.flavor.manifest.BuildCommittish)
}

func (p publication) destination() cloudprovider.Destination {
	return cloudprovider.Destination{
		Target: p.target.Type(),
		Key:    p.destinationKey,
	}
}

func (p publication) publishingGroup() string {
	return p.target.DestinationPublishingGroup(p.destinationKey)
}
