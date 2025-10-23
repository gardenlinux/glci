package task

import (
	"context"
	"errors"
	"fmt"
	"os"
)

func init() {
	registerStatePersistor(func() StatePersistor {
		return &file{}
	})
}

func (*file) Type() string {
	return "File"
}

func (*file) SetCredentials(_ map[string]any) error {
	return nil
}

func (*file) SetStateConfig(_ context.Context, _ any) error {
	return nil
}

func (p *file) SetID(id string) {
	p.key = "state_" + id + ".json"
}

func (*file) Close() error {
	return nil
}

func (p *file) Load() ([]byte, error) {
	if !p.isConfigured() {
		return nil, errors.New("config or ID not set")
	}

	state, err := os.ReadFile(p.key)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot read file %s: %w", p.key, err)
		}
		return nil, nil
	}

	return state, nil
}

func (p *file) Save(state []byte) error {
	if !p.isConfigured() {
		return errors.New("config or ID not set")
	}

	err := os.WriteFile(p.key, state, 0o644)
	if err != nil {
		return fmt.Errorf("cannot write file %s: %w", p.key, err)
	}

	return nil
}

func (p *file) Clear() error {
	if !p.isConfigured() {
		return errors.New("config or ID not set")
	}

	err := os.Remove(p.key)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove file %s: %w", p.key, err)
	}

	return nil
}

type file struct {
	key string
}

func (p *file) isConfigured() bool {
	return p.key != ""
}
