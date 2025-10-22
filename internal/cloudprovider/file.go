package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/gardenlinux/glci/internal/log"
)

func init() {
	registerOCMTarget(func() OCMTarget {
		return &file{}
	})
}

func (*file) Type() string {
	return "File"
}

func (*file) SetCredentials(_ map[string]any) error {
	return nil
}

func (p *file) SetOCMConfig(_ context.Context, cfg map[string]any) error {
	err := setConfig(cfg, &p.fileCfg)
	if err != nil {
		return err
	}

	return nil
}

func (*file) Close() error {
	return nil
}

func (*file) OCMType() string {
	t, err := NewOCMTarget("OCI")
	if err != nil {
		return ""
	}
	return t.OCMType()
}

func (p *file) OCMRepository() string {
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

type file struct {
	fileCfg fileOCMConfig
}

type fileOCMConfig struct {
	File       string `mapstructure:"file"`
	Repository string `mapstructure:"repository"`
}

func (p *file) isConfigured() bool {
	return p.fileCfg.File != ""
}
