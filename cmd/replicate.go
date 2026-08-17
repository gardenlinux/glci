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

func replicateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "replicate",
		Short: "Replicate Garden Linux release artifacts to their China artifact sources",
		Args:  cobra.NoArgs,
		RunE:  cli.RunFunc(replicate),
	}

	c.Flags().StringP("version", "v", "", "release version")
	c.Flags().StringP("commit", "c", "", "release commit(ish)")

	return c
}

func replicate(ctx context.Context, cfg *viper.Viper, _ []string) error {
	log.Info(ctx, "GLCI", "version", version)

	g, err := glci.New(cfg.AllSettings())
	if err != nil {
		return err
	}

	var stop func() error
	stop, err = g.Start(ctx, g.Publisher.ReplicationSources()...)
	if err != nil {
		return fmt.Errorf("cannot start artifact sources: %w", err)
	}
	defer func() {
		_ = stop()
	}()

	err = g.Publisher.Replicate(ctx, cfg.GetString("version"), cfg.GetString("commit"))
	if err != nil {
		return err
	}

	return stop()
}
