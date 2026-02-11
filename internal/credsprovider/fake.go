package credsprovider

import (
	"context"
)

func init() {
	registerCredsSource(func() CredsSource {
		return &fake{}
	})
}

type fake struct{}

func (*fake) Type() string {
	return "Fake"
}

func (*fake) SetCredsConfig(_ context.Context, _ map[string]any) error {
	return nil
}

func (*fake) AcquireCreds(_ context.Context, _ CredsID, _ UpdatedFunc) error {
	return nil
}

func (*fake) AcquireValidatedCreds(_ context.Context, _ CredsID, _ ValidateFunc, _ UpdatedFunc) error {
	return nil
}

func (*fake) ReleaseCreds(CredsID) {
}

func (*fake) Close() error {
	return nil
}
