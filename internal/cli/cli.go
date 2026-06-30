package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//nolint:gochecknoglobals // This needs to be set as early as possible.
var startTime time.Time

//nolint:gochecknoinits // This needs to be run as early as possible.
func init() {
	startTime = time.Now()
}

type (
	ctxkCfg   struct{}
	ctxkVer   struct{}
	ctxkStart struct{}
)

// StartTime returns the approximate start time of the process.
func StartTime() time.Time {
	return startTime
}

// WithVersion stores the version string into the context.
func WithVersion(ctx context.Context, version string) context.Context {
	return context.WithValue(ctx, ctxkVer{}, version)
}

// Version returns the version string stored in the context, or empty if unset.
func Version(ctx context.Context) string {
	ver, _ := ctx.Value(ctxkVer{}).(string)
	return ver
}

// WithStart stores the start time into the context.
func WithStart(ctx context.Context, start time.Time) context.Context {
	return context.WithValue(ctx, ctxkStart{}, start)
}

// ExecTime returns the duration since the start time stored in context, or 0 if unset.
func ExecTime(ctx context.Context) time.Duration {
	start, ok := ctx.Value(ctxkStart{}).(time.Time)
	if !ok {
		return 0
	}
	return time.Since(start)
}

// Setup creates a Cobra command with Viper configuration support.
// The define callback configures the command structure (flags, subcommands, metadata).
// The initialize callback fires after flags are bound and config is loaded, and can be used to enrich the context.
// The returned function returns the context that was returned by initialize, or the root command context if initialize did not succeed.
func Setup(name string, define func(*cobra.Command), initialize func(context.Context, *viper.Viper) (context.Context, error),
) (*cobra.Command, func() context.Context, error) {
	rootCmd := &cobra.Command{
		Version: "unknown",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("no command specified")
		},
	}

	cfg := viper.New()
	cfg.SetConfigName(name)
	cfg.AddConfigPath(".")
	cfg.SetEnvPrefix(strings.ToUpper(name))
	cfg.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	cfg.AutomaticEnv()

	var initializedCtx context.Context

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if cmd.Name() == cobra.ShellCompRequestCmd || cmd.Name() == cobra.ShellCompNoDescRequestCmd {
			return nil
		}

		err := cfg.BindPFlags(cmd.Flags())
		if err != nil {
			return fmt.Errorf("cannot bind flags: %w", err)
		}
		err = cfg.BindPFlags(cmd.InheritedFlags())
		if err != nil {
			return fmt.Errorf("cannot bind inherited flags: %w", err)
		}

		cfgFile := cfg.GetString("config-file")
		if cfgFile != "" {
			cfg.SetConfigFile(cfgFile)
		}

		err = cfg.ReadInConfig()
		if err != nil {
			_, ok := errors.AsType[viper.ConfigFileNotFoundError](err)
			if cfgFile != "" || !ok {
				return fmt.Errorf("cannot read config file: %w", err)
			}
		}

		if initialize != nil {
			var ctx context.Context
			ctx, err = initialize(cmd.Context(), cfg)
			if err != nil {
				return fmt.Errorf("cannot initialize: %w", err)
			}
			//nolint:fatcontext // This is required for ctxFunc closure to return the initialized context.
			initializedCtx = ctx
			cmd.SetContext(initializedCtx)
		}

		return nil
	}

	if define != nil {
		define(rootCmd)
	}

	initializedCtx = context.WithValue(context.Background(), ctxkCfg{}, cfg)
	rootCmd.SetContext(initializedCtx)

	return rootCmd, func() context.Context {
		return initializedCtx
	}, nil
}

// RunFunc wraps a function as a Cobra run handler with Viper support.
func RunFunc(run func(context.Context, *viper.Viper, []string) error) func(*cobra.Command, []string) error {
	return func(c *cobra.Command, args []string) error {
		c.SilenceErrors = true
		c.SilenceUsage = true

		ctx := c.Context()
		v, ok := ctx.Value(ctxkCfg{}).(*viper.Viper)
		if !ok {
			return errors.New("invalid context")
		}

		return run(ctx, v, args)
	}
}
