package glci

import (
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
)

// FlavorsConfig specifies what flavors of Garden Linux are to be worked on.
type FlavorsConfig struct {
	Flavors []cfgFlavor `mapstructure:"flavors"`
}

// Validate ensures that the flavours configuration is valid.
func (c *FlavorsConfig) Validate() error {
	for _, flavor := range c.Flavors {
		_, err := cloudprovider.NewPublishingTarget(flavor.Platform)
		if err != nil {
			return fmt.Errorf("invalid flavor %s: %w", flavor.Cname, err)
		}
	}

	return nil
}

// PublishingConfig contains configuration for GLCI itself and for each cloud provider.
type PublishingConfig struct {
	ManifestSource string      `mapstructure:"manifest_source"`
	ManifestTarget *string     `mapstructure:"manifest_target,omitempty"`
	Sources        []cfgSource `mapstructure:"sources"`
	Targets        []cfgTarget `mapstructure:"targets"`
	OCM            cfgTarget   `mapstructure:"ocm"`
}

// Validate ensures that the publishing configuration is valid.
func (c *PublishingConfig) Validate() error {
	ids := make(map[string]struct{}, len(c.Sources))
	for _, source := range c.Sources {
		_, err := cloudprovider.NewArtifactSource(source.Type)
		if err != nil {
			return fmt.Errorf("invalid source %s: %w", source.ID, err)
		}

		_, dup := ids[source.ID]
		if dup {
			return fmt.Errorf("duplicate source %s", source.ID)
		}
		ids[source.ID] = struct{}{}
	}
	_, ok := ids[c.ManifestSource]
	if !ok {
		return fmt.Errorf("missing manifest source %s", c.ManifestSource)
	}
	if c.ManifestTarget != nil {
		_, ok = ids[*c.ManifestTarget]
		if !ok {
			return fmt.Errorf("missing manifest target %s", *c.ManifestTarget)
		}
	}

	for _, target := range c.Targets {
		_, err := cloudprovider.NewPublishingTarget(target.Type)
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
	}

	_, err := cloudprovider.NewOCMTarget(c.OCM.Type)
	if err != nil {
		return fmt.Errorf("invalid OCM target: %w", err)
	}

	return nil
}

type cfgFlavor struct {
	Platform string `mapstructure:"platform"`
	Cname    string `mapstructure:"cname"`
}

type cfgSource struct {
	ID     string         `mapstructure:"id"`
	Type   string         `mapstructure:"type"`
	Config map[string]any `mapstructure:",remain"`
}

type cfgTarget struct {
	Type   string         `mapstructure:"type"`
	Config map[string]any `mapstructure:",remain"`
}

// AliasesConfig contains package aliases which are reflected in the component descriptor.
type AliasesConfig map[string][]string

// Validate ensures that the aliases configuration is valid.
func (*AliasesConfig) Validate() error {
	return nil
}
