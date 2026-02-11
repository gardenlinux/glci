package credsprovider

import (
	"context"
	"fmt"

	"github.com/go-viper/mapstructure/v2"
)

//nolint:gochecknoglobals // Required for automatic registration.
var (
	sources = make(map[string]newCredsSourceFunc)
)

// CredsSource is a source of credentials.
type CredsSource interface {
	Type() string
	SetCredsConfig(ctx context.Context, config map[string]any) error
	AcquireCreds(ctx context.Context, id CredsID, updated UpdatedFunc) error
	AcquireValidatedCreds(ctx context.Context, id CredsID, validate ValidateFunc, updated UpdatedFunc) error
	ReleaseCreds(id CredsID)
	Close() error
}

// CredsID is an identifier consisting of the type of credential and the specific configuration within that type.
type CredsID struct {
	Type   string
	Config string
}

// ValidateFunc is a callback function that checks whether the credentials work correctly.
type ValidateFunc func(ctx context.Context, creds map[string]any) (bool, error)

// UpdatedFunc is a callback function that is invoked when credentials are updated.
type UpdatedFunc func(ctx context.Context, creds map[string]any) error

// NewCredsSource returns a new CredsSource of a given type.
func NewCredsSource(typ string) (CredsSource, error) {
	nf, ok := sources[typ]
	if !ok {
		return nil, fmt.Errorf("credentialss source %s is not supported", typ)
	}

	return nf(), nil
}

type newCredsSourceFunc func() CredsSource

func registerCredsSource(nf newCredsSourceFunc) {
	sources[nf().Type()] = nf
}

func setConfig[CONFIG any](cfg map[string]any, config *CONFIG) error {
	err := mapstructure.Decode(cfg, &config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return nil
}
