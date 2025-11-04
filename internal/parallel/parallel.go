package parallel

import (
	"context"
	"errors"

	"github.com/wandb/parallel"

	"github.com/gardenlinux/glci/internal/log"
)

// WithInlineMode stores an inline mode into the context.
func WithInlineMode(ctx context.Context, inline bool) context.Context {
	return context.WithValue(ctx, ctxkInline{}, inline)
}

// Activity is a parallel activity that can swawn goroutines and wait for them.
type Activity[T any] interface {
	Go(f ActivityFunc[T])
	Wait() error
}

// ActivityFunc is a function that runs in a goroutine and produces a value.
type ActivityFunc[T any] func(context.Context) (T, error)

// ResultFunc is a function that runs synchronized and processes a produced value.
type ResultFunc[T any] func(context.Context, T) error

// NoResult is an empty result.
type NoResult struct{}

// NewActivity creates a new activity, either parallel or inline, with a given result function.
func NewActivity[T any](ctx context.Context, rf ResultFunc[T]) Activity[T] {
	inline, _ := ctx.Value(ctxkInline{}).(bool)
	if inline {
		return &inlineActivity[T]{
			ctx:        ctx,
			resultFunc: rf,
		}
	}

	if rf == nil {
		rf = func(_ context.Context, _ T) error {
			return nil
		}
	}

	return &parallelActivity[T]{
		ctx:  ctx,
		exec: parallel.FeedWithErrs[T](parallel.Unlimited(ctx), rf),
	}
}

func (a *parallelActivity[T]) Go(f ActivityFunc[T]) {
	a.exec.Go(f)
}

func (a *parallelActivity[T]) Wait() error {
	return printErrs(a.ctx, a.exec.Wait())
}

func (a *inlineActivity[T]) Go(f ActivityFunc[T]) {
	r, err := f(a.ctx)
	if err != nil {
		a.errs = append(a.errs, err)
	} else if a.resultFunc != nil {
		err = a.resultFunc(a.ctx, r)
		if err != nil {
			a.errs = append(a.errs, err)
		}
	}
}

func (a *inlineActivity[T]) Wait() error {
	return printErrs(a.ctx, parallel.CombineErrors(a.errs...))
}

type (
	ctxkInline struct{}
)

type parallelActivity[T any] struct {
	ctx  context.Context
	exec parallel.FeedingAllErrsExecutor[T]
}

type inlineActivity[T any] struct {
	ctx        context.Context
	resultFunc ResultFunc[T]
	errs       []error
}

func printErrs(ctx context.Context, err error) error {
	if err != nil {
		var terr parallel.MultiError
		if errors.As(err, &terr) {
			errs := terr.Unwrap()
			log.ErrorMsg(ctx, "Errors encountered during parallel execution", "cnt", len(errs))
			for _, er := range errs {
				log.Error(ctx, er)
			}
		}
	}

	return err
}
