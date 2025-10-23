package main

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gardenlinux/glci/internal/cmd"
	"github.com/gardenlinux/glci/internal/glci"
	"github.com/gardenlinux/glci/internal/log"
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
	c.Flags().Bool("omit-component-descriptor", false, "omit publishing a component descriptor")

	return c
}

func publish(ctx context.Context, cfg *viper.Viper) error {
	log.Info(ctx, "GLCI", "version", version)

	flavorsCfg, publishingCfg, aliasesCfg, creds, err := loadConfigAndCredentials(ctx, cfg)
	if err != nil {
		return err
	}

	return glci.Publish(ctx, flavorsCfg, publishingCfg, aliasesCfg, creds, cfg.GetString("version"), cfg.GetString("commit"),
		cfg.GetBool("omit-component-descriptor"))
}
