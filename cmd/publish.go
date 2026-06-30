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

func publishCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "publish",
		Short: "Publish a Garden Linux release to cloud providers",
		Args:  cobra.NoArgs,
		RunE:  cli.RunFunc(publish),
	}

	c.Flags().StringP("version", "v", "", "release version")
	c.Flags().StringP("commit", "c", "", "release commit(ish)")
	c.Flags().Bool("omit-component-descriptor", false, "omit publishing a component descriptor")

	return c
}

func publish(ctx context.Context, cfg *viper.Viper, _ []string) error {
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

	err = g.Publisher.Publish(ctx, cfg.GetString("version"), cfg.GetString("commit"), cfg.GetBool("omit-component-descriptor"))
	if err != nil {
		return err
	}

	return stop()
}
