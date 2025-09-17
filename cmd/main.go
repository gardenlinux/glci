package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/gardenlinux/glci/internal/cmd"
	"github.com/gardenlinux/glci/internal/glci"
	"github.com/gardenlinux/glci/internal/log"
)

func main() {
	var exitCode int
	defer func() {
		os.Exit(exitCode)
	}()

	mainCmd, cfg, err := cmd.Setup("glci", func(c *cobra.Command) {
		c.Use = "glci"
		c.Short = "GLCI - Garden Linux continuous integration"
		c.Version = version
		c.PersistentFlags().Bool("dev", false, "run in development mode")
		c.PersistentFlags().String("config-file", "", "path to configuration file")
		c.AddCommand(publishCmd(), removeCmd())
	})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		exitCode = 1
		return
	}

	ctx, stop := signal.NotifyContext(log.Setup(mainCmd.Context(), cfg.GetBool("dev"), false, os.Stderr), syscall.SIGTERM,
		syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	defer stop()

	err = mainCmd.ExecuteContext(glci.WithVersion(glci.WithStart(ctx, cmd.StartTime()), version))
	if err != nil {
		log.Error(ctx, err)
		exitCode = 1
		return
	}
}
