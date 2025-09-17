package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() { // nolint:gochecknoinits // This needs to be run as early as possible.
	startTime = time.Now()
}

// Setup sets up a Cobra command in such a way that it supports integration with Viper.
func Setup(name string, build func(*cobra.Command)) (*cobra.Command, *viper.Viper, error) {
	rootCmd := &cobra.Command{}
	rootCmd.Version = "unknown"

	if build != nil {
		build(rootCmd)
	}

	cfg := viper.New()
	cfg.SetConfigName(name)
	cfg.AddConfigPath(".")
	rootCmd.SetContext(context.WithValue(context.Background(), ctxkCfg{}, cfg))

	if len(os.Args) > 1 && os.Args[1] != cobra.ShellCompRequestCmd && os.Args[1] != cobra.ShellCompNoDescRequestCmd {
		rootCmd.InitDefaultHelpCmd()
		rootCmd.InitDefaultCompletionCmd(os.Args[1:]...)

		cmd, args, err := rootCmd.Find(os.Args[1:])
		if err != nil {
			return nil, nil, err //nolint:wrapcheck // Directly wraps the Cobra error message.
		}

		cmd.InitDefaultHelpFlag()
		cmd.InitDefaultVersionFlag()

		err = cmd.ParseFlags(args)
		if err != nil {
			return nil, nil, err //nolint:wrapcheck // Directly wraps the Cobra error message.
		}

		err = cfg.BindPFlags(cmd.Flags())
		if err != nil {
			return nil, nil, err //nolint:wrapcheck // Directly wraps the Viper error message.
		}
		cfg.SetEnvPrefix(strings.ToUpper(rootCmd.Name()))
		cfg.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		cfg.AutomaticEnv()

		cfgFile := cfg.GetString("config-file")
		if cfgFile != "" {
			cfg.SetConfigFile(cfgFile)
		}

		err = cfg.ReadInConfig()
		if err != nil {
			if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
				return nil, nil, fmt.Errorf("cannot read config file: %w", err)
			}
		}
	}

	return rootCmd, cfg, nil
}

// RunFunc adds a run function to a Cobra command in a way that it support Viper.
func RunFunc(run func(context.Context, *viper.Viper) error) func(*cobra.Command, []string) error {
	return func(c *cobra.Command, _ []string) error {
		c.SilenceErrors = true
		c.SilenceUsage = true

		ctx := c.Context()
		v, ok := ctx.Value(ctxkCfg{}).(*viper.Viper)
		if !ok {
			return errors.New("invalid context")
		}

		return run(ctx, v)
	}
}

// StartTime returns the approximate start time of the process.
func StartTime() time.Time {
	return startTime
}

var startTime time.Time // nolint:gochecknoglobals // This needs to be set as early as possible.

type ctxkCfg struct{}
