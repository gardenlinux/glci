package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	module.RegisterImpl(OCMTargetCategory, "File", func(b *module.Base) OCMTarget {
		return &file{
			base: b,
		}
	})
}

func (*file) Type() string {
	return "File"
}

type file struct {
	base *module.Base

	fileCfg fileOCMConfig
}

type fileOCMConfig struct {
	File       string `mapstructure:"file"`
	Repository string `mapstructure:"repository"`
}

func (p *file) isConfigured() bool {
	return p.fileCfg.File != ""
}

func (*file) OCMType() string {
	return (*oci)(nil).OCMType()
}

func (p *file) OCMRepositoryBase() string {
	return p.fileCfg.Repository
}

func (p *file) PublishComponentDescriptor(ctx context.Context, _ string, descriptor []byte) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "repo", p.fileCfg.File)

	log.Debug(ctx, "Writing file", "file", p.fileCfg.File)
	err := os.WriteFile(p.fileCfg.File, descriptor, 0o644)
	if err != nil {
		return fmt.Errorf("cannot write file %s: %w", p.fileCfg.File, err)
	}

	return nil
}

func (p *file) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.fileCfg)
	if err != nil {
		return err
	}

	return nil
}

func (*file) Configurables() []module.Configurable {
	return nil
}

func (*file) Start(_ context.Context) error {
	return nil
}

func (*file) Stop() error {
	return nil
}
