package concurrency

import (
	"context"
	"errors"

	"github.com/gardenlinux/glci/internal/log"
)

type (
	ctxkInline struct{}
)

// WithInlineMode stores an inline mode into the context.
func WithInlineMode(ctx context.Context, inline bool) context.Context {
	return context.WithValue(ctx, ctxkInline{}, inline)
}

// ResultSyncFunc is a function that runs synchronized to process a result.
type ResultSyncFunc func() error

type loggedError struct {
	err error
}

func (e *loggedError) Error() string {
	return e.err.Error()
}

func (e *loggedError) Unwrap() error {
	return e.err
}

func logOnce(ctx context.Context, err error) error {
	_, ok := errors.AsType[*loggedError](err)
	if ok {
		return err
	}

	log.Error(ctx, err)

	return &loggedError{
		err: err,
	}
}
