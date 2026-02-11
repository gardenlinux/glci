package main

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gardenlinux/glci/internal/cmd"
	"github.com/gardenlinux/glci/internal/glci"
	"github.com/gardenlinux/glci/internal/log"
)

func removeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "remove",
		Short: "remove a Garden Linux release from cloud providers",
		Args:  cobra.NoArgs,
		RunE:  cmd.RunFunc(remove),
	}

	c.Flags().StringP("version", "v", "", "release version")
	c.Flags().StringP("commit", "c", "", "release commit(ish)")
	c.Flags().Bool("steamroll", false, "ignore errors while destroying things")

	return c
}

func remove(ctx context.Context, cfg *viper.Viper) error {
	log.Info(ctx, "GLCI", "version", version)

	flavorsCfg, publishingCfg, _, err := loadConfig(ctx, cfg)
	if err != nil {
		return err
	}

	return glci.Remove(ctx, flavorsCfg, publishingCfg, cfg.GetString("version"), cfg.GetString("commit"), cfg.GetBool("steamroll"))
}
