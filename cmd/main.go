package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gardenlinux/glci/internal/cli"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/parallel"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	mainCmd, cmdCtx, err := cli.Setup("glci", func(c *cobra.Command) {
		c.Use = "glci"
		c.Short = "GLCI - Garden Linux continuous integration"
		c.Version = version
		c.PersistentFlags().Bool("debug", false, "log at debug level")
		c.PersistentFlags().Bool("glacial", false, "disable all parallelism")
		c.PersistentFlags().String("config-file", "", "path to configuration file")
		c.AddCommand(publishCmd(), removeCmd())
	}, func(ctx context.Context, cfg *viper.Viper) (context.Context, error) {
		ctx = log.Setup(ctx, cfg.GetBool("debug"), false, os.Stderr)
		if cfg.GetBool("glacial") {
			ctx = parallel.WithInlineMode(ctx, true)
		}
		ctx = cli.WithVersion(ctx, version)
		ctx = cli.WithStart(ctx, cli.StartTime())
		return ctx, nil
	})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}

	ctx, stop := signal.NotifyContext(mainCmd.Context(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()

	err = mainCmd.ExecuteContext(ctx)
	ctx = cmdCtx()
	if err != nil {
		log.ErrorAnyway(ctx, err)
		return 1
	}

	return 0
}
