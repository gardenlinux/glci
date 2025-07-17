package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/viper"

	"github.com/gardenlinux/glci/internal/glci"
	"github.com/gardenlinux/glci/internal/log"
)

func loadConfigAndCredentials(ctx context.Context, cfg *viper.Viper) (glci.FlavorsConfig, glci.PublishingConfig, glci.AliasesConfig,
	glci.Credentials, error,
) {
	log.Debug(ctx, "Loading configuration and credentials")

	fcfg := cfg.Sub("flavors")
	if fcfg == nil {
		return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, errors.New("missing flavors configuration")
	}
	var flavorsCfg glci.FlavorsConfig
	err := fcfg.Unmarshal(&flavorsCfg)
	if err != nil {
		return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, fmt.Errorf("invalid flavors configuration: %w", err)
	}
	err = flavorsCfg.Validate()
	if err != nil {
		return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, fmt.Errorf("invalid flavors configuration: %w", err)
	}

	pcfg := cfg.Sub("publishing")
	if pcfg == nil {
		return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, errors.New("missing publishing configuration")
	}
	var publishingCfg glci.PublishingConfig
	err = pcfg.Unmarshal(&publishingCfg)
	if err != nil {
		return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, fmt.Errorf("invalid publishing configuration: %w", err)
	}
	err = publishingCfg.Validate()
	if err != nil {
		return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, fmt.Errorf("invalid publishing configuration: %w", err)
	}

	acfg := cfg.Sub("aliases")
	var aliasesCfg glci.AliasesConfig
	if acfg != nil {
		err = acfg.Unmarshal(&aliasesCfg)
		if err != nil {
			return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, fmt.Errorf("invalid aliases configuration: %w", err)
		}
		err = aliasesCfg.Validate()
		if err != nil {
			return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, fmt.Errorf("invalid aliases configuration: %w", err)
		}
	}

	var creds glci.Credentials
	creds, err = glci.LoadCredentials(ctx, cfg.GetString("credentials-file"), cfg.GetString("credentials-base64"))
	if err != nil {
		return glci.FlavorsConfig{}, glci.PublishingConfig{}, nil, nil, fmt.Errorf("cannot load credentials: %w", err)
	}

	return flavorsCfg, publishingCfg, aliasesCfg, creds, nil
}
