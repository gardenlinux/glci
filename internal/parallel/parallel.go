package parallel

import (
	"context"
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
