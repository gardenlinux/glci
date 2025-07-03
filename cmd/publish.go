package main

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gardenlinux/glci/internal/cmd"
	"github.com/gardenlinux/glci/internal/glci"
)

func publishCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "publish",
		Short: "Publish a Garden Linux release to cloud providers",
		Args:  cobra.NoArgs,
		RunE:  cmd.RunFunc(publish),
	}

	c.Flags().String("credentials-file", "", "path to credentials YAML file")
	c.Flags().String("credentials-base64", "", "base64 encoded credentials YAML (overrides --credentials-file)")
	c.Flags().StringP("version", "v", "", "release version")
	c.Flags().StringP("commit", "c", "", "release commit(ish)")

	return c
}

func publish(ctx context.Context, cfg *viper.Viper) error {
	flavorsCfg, publishingCfg, aliasesCfg, creds, err := loadConfigAndCredentials(ctx, cfg)
	if err != nil {
		return err
	}

	//nolint:wrapcheck // Directly wraps the GLCI command.
	return glci.Publish(ctx, flavorsCfg, publishingCfg, aliasesCfg, creds, cfg.GetString("version"), cfg.GetString("commit"))
}
