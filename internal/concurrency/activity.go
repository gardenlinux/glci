package concurrency

import (
	"context"
	"errors"

	"github.com/wandb/parallel"
)

// Activity is a parallel activity that can spawn goroutines and wait for them.
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
	//nolint:contextcheck // Forwards caller context, not parallel's group context.
	a.exec.Go(func(_ context.Context) error {
		inErr := f(a.ctx)
		if inErr != nil {
			inErr = logOnce(a.ctx, inErr)
		}

		return inErr
	})
}

func (a *parallelActivity) Wait() error {
	return normalize(a.exec.Wait())
}

type inlineActivity struct {
	ctx  context.Context
	errs []error
}

func (a *inlineActivity) Go(f ActivityFunc) {
	err := f(a.ctx)
	if err != nil {
		a.errs = append(a.errs, logOnce(a.ctx, err))
	}
}

func (a *inlineActivity) Wait() error {
	return errors.Join(a.errs...)
}

// ActivitySync is a parallel activity that can spawn goroutines, sync them, and wait for them.
type ActivitySync interface {
	Go(f ActivitySyncFunc)
	Wait() error
}

// ActivitySyncFunc is a function that runs in a goroutine and returns a ResultSyncFunc to sync the result.
type ActivitySyncFunc func(context.Context) (ResultSyncFunc, error)

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
		exec: parallel.FeedWithErrs(exec, func(_ context.Context, rf ResultSyncFunc) error {
			if rf == nil {
				return nil
			}

			inErr := rf()
			if inErr != nil {
				inErr = logOnce(ctx, inErr)
			}
			return inErr
		}),
	}
}

type parallelActivitySync struct {
	ctx  context.Context
	exec parallel.FeedingAllErrsExecutor[ResultSyncFunc]
}

func (a *parallelActivitySync) Go(f ActivitySyncFunc) {
	//nolint:contextcheck // Forwards caller context, not parallel's group context.
	a.exec.Go(func(_ context.Context) (ResultSyncFunc, error) {
		rf, inErr := f(a.ctx)
		if inErr != nil {
			inErr = logOnce(a.ctx, inErr)
		}
		return rf, inErr
	})
}

func (a *parallelActivitySync) Wait() error {
	return normalize(a.exec.Wait())
}

type inlineActivitySync struct {
	ctx  context.Context
	errs []error
}

func (a *inlineActivitySync) Go(f ActivitySyncFunc) {
	rf, err := f(a.ctx)
	if err != nil {
		a.errs = append(a.errs, logOnce(a.ctx, err))
		return
	}
	if rf != nil {
		err = rf()
		if err != nil {
			a.errs = append(a.errs, logOnce(a.ctx, err))
		}
	}
}

func (a *inlineActivitySync) Wait() error {
	return errors.Join(a.errs...)
}

func normalize(err error) error {
	multiErr, ok := err.(parallel.MultiError) //nolint:errorlint // Intentional exact error assertion.
	if !ok {
		return err
	}

	return errors.Join(multiErr.Unwrap()...)
}
