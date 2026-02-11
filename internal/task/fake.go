package task

import (
	"context"

	"github.com/gardenlinux/glci/internal/credsprovider"
)

func init() {
	registerStatePersistor(func() StatePersistor {
		return &fake{}
	})
}

type fake struct{}

func (*fake) Type() string {
	return "Fake"
}

func (*fake) SetStateConfig(_ context.Context, _ credsprovider.CredsSource, _ any) error {
	return nil
}

func (*fake) SetID(_ string) {
}

func (*fake) Close() error {
	return nil
}

func (*fake) Load() ([]byte, error) {
	return nil, nil
}

func (*fake) Save(_ []byte) error {
	return nil
}

func (*fake) Clear() error {
	return nil
}
