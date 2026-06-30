package credsprovider

import (
	"context"
	"fmt"

	"github.com/go-viper/mapstructure/v2"

	"github.com/gardenlinux/glci/internal/module"
)

// Category is the module framework registry for CredsSource implementations.
//
//nolint:gochecknoglobals // Required for automatic registration.
var Category = module.NewCategory[CredsSource]()

// CredsSource is a source of credentials.
type CredsSource interface {
	module.Module

	Type() string
	AcquireCreds(ctx context.Context, id CredsID, updated UpdatedFunc) error
	AcquireValidatedCreds(ctx context.Context, id CredsID, validate ValidateFunc, updated UpdatedFunc) error
	ReleaseCreds(id CredsID)
}

// CredsID is an identifier consisting of the type of credential and the specific configuration within that type.
type CredsID struct {
	Type   string
	Config string
	Role   string
}

// ValidateFunc is a callback function that checks whether the credentials work correctly.
type ValidateFunc func(ctx context.Context, creds map[string]any) (bool, error)

// UpdatedFunc is a callback function that is invoked when credentials are updated.
type UpdatedFunc func(ctx context.Context, creds map[string]any) error

func parseConfig[CONFIG any](cfg map[string]any, config *CONFIG) error {
	err := mapstructure.Decode(cfg, &config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return nil
}
