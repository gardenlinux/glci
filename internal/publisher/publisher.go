package publisher

import (
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/task"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	module.RegisterSchema((*Publisher)(nil), &publisherConfig{})
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
	state          task.StatePersistor

	cfg     publisherConfig
	flavors []Flavor
	aliases map[string][]string
}

// Flavor is a Garden Linux release flavor.
type Flavor struct {
	Platform string `mapstructure:"platform"`
	Cname    string `mapstructure:"cname"`
}

type publisherConfig struct {
	Credentials    module.Slot[credsprovider.CredsSource]           `mapstructure:"credentials"`
	Sources        module.SliceSlot[cloudprovider.ArtifactSource]   `mapstructure:"sources"`
	ManifestSource string                                           `mapstructure:"manifest_source"`
	ManifestTarget string                                           `mapstructure:"manifest_target,omitzero"`
	Targets        module.SliceSlot[cloudprovider.PublishingTarget] `mapstructure:"targets"`
	OCM            module.Slot[cloudprovider.OCMTarget]             `mapstructure:"ocm"`
	State          module.Slot[task.StatePersistor]                 `mapstructure:"state"`
	Flavors        flavorsConfig                                    `mapstructure:"flavors"`
	Aliases        map[string][]string                              `mapstructure:"aliases,omitempty"`
}

type flavorsConfig struct {
	Flavors []Flavor `mapstructure:"flavors"`
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

	p.flavors = p.cfg.Flavors.Flavors
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
	p.state, err = module.ConfigureModule(p.base, task.Category, p.cfg.State)
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
