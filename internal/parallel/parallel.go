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
type Activity interface {
	Go(f ActivityFunc)
	Wait() error
}

// ActivitySync is a parallel activity that can swawn goroutines, sync them, and wait for them.
type ActivitySync interface {
	Go(f ActivitySyncFunc)
	Wait() error
}

// ActivityFunc is a function that runs in a goroutine.
type ActivityFunc func(context.Context) error

// ActivitySyncFunc is a function that runs in a goroutine and returns a ResultFunc to sync the result.
type ActivitySyncFunc func(context.Context) (ResultFunc, error)

// ResultFunc is a function that runs synchronized to process a result.
type ResultFunc func() error

// NewActivity creates a new activity, either parallel or inline.
func NewActivity(ctx context.Context) Activity {
	inline, _ := ctx.Value(ctxkInline{}).(bool)
	if inline {
		return &inlineActivity{
			ctx: ctx,
		}
	}

	return &parallelActivity{
		ctx:  ctx,
		exec: parallel.GatherErrs(parallel.Unlimited(ctx)),
	}
}

// NewActivitySync creates a new activity, either parallel or inline, with a given result function.
func NewActivitySync(ctx context.Context) ActivitySync {
	inline, _ := ctx.Value(ctxkInline{}).(bool)
	if inline {
		return &inlineActivitySync{
			ctx: ctx,
		}
	}

	return &parallelActivitySync{
		ctx: ctx,
		exec: parallel.FeedWithErrs(parallel.Unlimited(ctx), func(_ context.Context, rf ResultFunc) error {
			if rf == nil {
				return nil
			}

			return rf()
		}),
	}
}

func (a *parallelActivity) Go(f ActivityFunc) {
	a.exec.Go(f)
}

func (a *parallelActivity) Wait() error {
	return printErrs(a.ctx, a.exec.Wait())
}

func (a *parallelActivitySync) Go(f ActivitySyncFunc) {
	a.exec.Go(f)
}

func (a *parallelActivitySync) Wait() error {
	return printErrs(a.ctx, a.exec.Wait())
}

func (a *inlineActivity) Go(f ActivityFunc) {
	err := f(a.ctx)
	if err != nil {
		a.errs = append(a.errs, err)
	}
}

func (a *inlineActivity) Wait() error {
	return printErrs(a.ctx, parallel.CombineErrors(a.errs...))
}

func (a *inlineActivitySync) Go(f ActivitySyncFunc) {
	rf, err := f(a.ctx)
	if err != nil {
		a.errs = append(a.errs, err)
		return
	}
	if rf != nil {
		err = rf()
		if err != nil {
			a.errs = append(a.errs, err)
		}
	}
}

func (a *inlineActivitySync) Wait() error {
	return printErrs(a.ctx, parallel.CombineErrors(a.errs...))
}

type (
	ctxkInline struct{}
)

type parallelActivity struct {
	ctx  context.Context
	exec parallel.AllErrsExecutor
}

type parallelActivitySync struct {
	ctx  context.Context
	exec parallel.FeedingAllErrsExecutor[ResultFunc]
}

type inlineActivity struct {
	ctx  context.Context
	errs []error
}

type inlineActivitySync struct {
	ctx  context.Context
	errs []error
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
