package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gardenlinux/glci/internal/cli"
	"github.com/gardenlinux/glci/internal/glci"
	"github.com/gardenlinux/glci/internal/log"
)

func unpublishCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "unpublish",
		Short: "Unpublish a Garden Linux release from cloud providers",
		Args:  cobra.NoArgs,
		RunE:  cli.RunFunc(unpublish),
	}

	c.Flags().StringP("version", "v", "", "release version")
	c.Flags().StringP("commit", "c", "", "release commit(ish)")
	c.Flags().Bool("steamroll", false, "ignore errors while destroying things")

	return c
}

func unpublish(ctx context.Context, cfg *viper.Viper, _ []string) error {
	log.Info(ctx, "GLCI", "version", version)

	g, err := glci.New(cfg.AllSettings())
	if err != nil {
		return err
	}

	var stop func() error
	stop, err = g.Start(ctx, g.Publisher)
	if err != nil {
		return fmt.Errorf("cannot start publisher: %w", err)
	}
	defer func() {
		_ = stop()
	}()

	err = g.Publisher.Unpublish(ctx, cfg.GetString("version"), cfg.GetString("commit"), cfg.GetBool("steamroll"))
	if err != nil {
		return err
	}

	return stop()
}
