package task

import (
	"context"
)

func init() {
	registerStatePersistor(func() StatePersistor {
		return &fake{}
	})
}

func (*fake) Type() string {
	return "Fake"
}

func (*fake) SetCredentials(_ map[string]any) error {
	return nil
}

func (*fake) SetStateConfig(_ context.Context, _ any) error {
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

type fake struct{}
