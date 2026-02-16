package parallel

import (
	"context"
	"errors"

	"github.com/wandb/parallel"

	"github.com/gardenlinux/glci/internal/log"
)

type (
	ctxkInline struct{}
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

// ActivityFunc is a function that runs in a goroutine.
type ActivityFunc func(context.Context) error

// NewActivity creates a new activity, either parallel or inline.
func NewActivity(ctx context.Context) Activity {
	return NewLimitedActivity(ctx, 0)
}

// NewLimitedActivity creates a new activity, either parallel or inline, with a given parallelism limit.
func NewLimitedActivity(ctx context.Context, limit int) Activity {
	inline, _ := ctx.Value(ctxkInline{}).(bool)
	if inline {
		return &inlineActivity{
			ctx: ctx,
		}
	}

	var exec parallel.Executor
	if limit == 0 {
		exec = parallel.Unlimited(ctx)
	} else {
		exec = parallel.Limited(ctx, limit)
	}

	return &parallelActivity{
		ctx:  ctx,
		exec: parallel.GatherErrs(exec),
	}
}

type parallelActivity struct {
	ctx  context.Context
	exec parallel.AllErrsExecutor
}

func (a *parallelActivity) Go(f ActivityFunc) {
	a.exec.Go(func(ctx context.Context) error {
		err := f(ctx)
		if err != nil {
			log.Error(ctx, err)
		}
		return err
	})
}

func (a *parallelActivity) Wait() error {
	return printErrs(a.ctx, a.exec.Wait())
}

type inlineActivity struct {
	ctx  context.Context
	errs []error
}

func (a *inlineActivity) Go(f ActivityFunc) {
	err := f(a.ctx)
	if err != nil {
		log.Error(a.ctx, err)
		a.errs = append(a.errs, err)
	}
}

func (a *inlineActivity) Wait() error {
	return printErrs(a.ctx, parallel.CombineErrors(a.errs...))
}

// ActivitySync is a parallel activity that can swawn goroutines, sync them, and wait for them.
type ActivitySync interface {
	Go(f ActivitySyncFunc)
	Wait() error
}

// ActivitySyncFunc is a function that runs in a goroutine and returns a ResultFunc to sync the result.
type ActivitySyncFunc func(context.Context) (ResultFunc, error)

// ResultFunc is a function that runs synchronized to process a result.
type ResultFunc func() error

// NewActivitySync creates a new activity, either parallel or inline, with a given result function.
func NewActivitySync(ctx context.Context) ActivitySync {
	return NewLimitedActivitySync(ctx, 0)
}

// NewLimitedActivitySync creates a new activity, either parallel or inline, with a given result function and a given parallelism limit.
func NewLimitedActivitySync(ctx context.Context, limit int) ActivitySync {
	inline, _ := ctx.Value(ctxkInline{}).(bool)
	if inline {
		return &inlineActivitySync{
			ctx: ctx,
		}
	}

	var exec parallel.Executor
	if limit == 0 {
		exec = parallel.Unlimited(ctx)
	} else {
		exec = parallel.Limited(ctx, limit)
	}

	return &parallelActivitySync{
		ctx: ctx,
		exec: parallel.FeedWithErrs(exec, func(_ context.Context, rf ResultFunc) error {
			if rf == nil {
				return nil
			}

			err := rf()
			if err != nil {
				log.Error(ctx, err)
			}
			return err
		}),
	}
}

type parallelActivitySync struct {
	ctx  context.Context
	exec parallel.FeedingAllErrsExecutor[ResultFunc]
}

func (a *parallelActivitySync) Go(f ActivitySyncFunc) {
	a.exec.Go(func(ctx context.Context) (ResultFunc, error) {
		rf, err := f(ctx)
		if err != nil {
			log.Error(ctx, err)
		}
		return rf, err
	})
}

func (a *parallelActivitySync) Wait() error {
	return printErrs(a.ctx, a.exec.Wait())
}

type inlineActivitySync struct {
	ctx  context.Context
	errs []error
}

func (a *inlineActivitySync) Go(f ActivitySyncFunc) {
	rf, err := f(a.ctx)
	if err != nil {
		log.Error(a.ctx, err)
		a.errs = append(a.errs, err)
		return
	}
	if rf != nil {
		err = rf()
		if err != nil {
			log.Error(a.ctx, err)
			a.errs = append(a.errs, err)
		}
	}
}

func (a *inlineActivitySync) Wait() error {
	return printErrs(a.ctx, parallel.CombineErrors(a.errs...))
}

func printErrs(ctx context.Context, err error) error {
	if err != nil {
		terr, ok := errors.AsType[parallel.MultiError](err)
		if ok {
			errs := terr.Unwrap()
			log.ErrorMsg(ctx, "Errors encountered during parallel execution", "cnt", len(errs))
		}
	}

	return err
}
