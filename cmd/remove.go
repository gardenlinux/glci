package main

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gardenlinux/glci/internal/cmd"
	"github.com/gardenlinux/glci/internal/glci"
)

func removeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "remove",
		Short: "remove a Garden Linux release from cloud providers",
		Args:  cobra.NoArgs,
		RunE:  cmd.RunFunc(remove),
	}

	c.Flags().String("credentials-file", "", "path to credentials YAML file")
	c.Flags().String("credentials-base64", "", "base64 encoded credentials YAML (overrides --credentials-file)")
	c.Flags().StringP("version", "v", "", "release version")
	c.Flags().StringP("commit", "c", "", "release commit(ish)")

	return c
}

func remove(ctx context.Context, cfg *viper.Viper) error {
	flavorsCfg, publishingCfg, _, creds, err := loadConfigAndCredentials(ctx, cfg)
	if err != nil {
		return err
	}

	//nolint:wrapcheck // Directly wraps the GLCI command.
	return glci.Remove(ctx, flavorsCfg, publishingCfg, creds, cfg.GetString("version"), cfg.GetString("commit"))
}
