package concurrency

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/graph"
)

// FailureMode controls how RunTasks reacts to a task that fails.
type FailureMode int

const (
	// FailureModeSkipDependents skips the transitive dependents of a failed task and runs the rest.
	FailureModeSkipDependents FailureMode = iota + 1
	// FailureModeStop stops dispatching new tasks after the first failure.
	FailureModeStop
	// FailureModeContinue keeps dispatching regardless of failures.
	FailureModeContinue
)

type completion[T comparable] struct {
	task       T
	err        error
	resultSync ResultSyncFunc
	panicked   bool
	panicVal   any
}

// RunTasks runs each task once after all its dependencies complete, concurrently, reacting to failures per mode.
func RunTasks[T comparable](ctx context.Context, tasks []T, dependencies func(T) ([]T, error), run func(context.Context, T) error,
	mode FailureMode,
) error {
	return runTasks(ctx, tasks, dependencies, func(ctx context.Context, t T) (ResultSyncFunc, error) {
		return nil, run(ctx, t)
	}, mode)
}

// RunTasksSync is like RunTasks but each task returns a ResultSyncFunc to sync its result.
func RunTasksSync[T comparable](ctx context.Context, tasks []T, dependencies func(T) ([]T, error),
	run func(context.Context, T) (ResultSyncFunc, error), mode FailureMode,
) error {
	return runTasks(ctx, tasks, dependencies, run, mode)
}

func runTasks[T comparable](ctx context.Context, tasks []T, dependencies func(T) ([]T, error),
	run func(context.Context, T) (ResultSyncFunc, error), mode FailureMode,
) error {
	if len(tasks) == 0 {
		return nil
	}

	switch mode {
	case FailureModeSkipDependents, FailureModeStop, FailureModeContinue:
	default:
		return fmt.Errorf("invalid failure mode %d", mode)
	}

	allTasks := make(map[T]struct{}, len(tasks))
	for _, t := range tasks {
		allTasks[t] = struct{}{}
	}

	dependents := make(map[T][]T, len(tasks))
	pendingDeps := make(map[T]int, len(tasks))
	_, err := graph.ReverseTopologicalSort(tasks, func(t T) ([]T, error) {
		deps, inErr := dependencies(t)
		if inErr != nil {
			return nil, fmt.Errorf("cannot get task dependencies: %w", inErr)
		}

		seen := make(map[T]struct{}, len(deps))
		for _, d := range deps {
			_, ok := seen[d]
			if ok {
				continue
			}
			seen[d] = struct{}{}

			_, ok = allTasks[d]
			if !ok {
				return nil, errors.New("task depends on a task that is not in the task set")
			}

			dependents[d] = append(dependents[d], t)
			pendingDeps[t]++
		}

		return deps, nil
	})
	if err != nil {
		return err
	}

	activity := NewActivity(ctx)
	completions := make(chan completion[T], len(tasks))
	runningTasks := 0

	for _, t := range tasks {
		if pendingDeps[t] == 0 {
			runningTasks++
			dispatchTask(ctx, activity, completions, run, t)
		}
	}

	skipped := make(map[T]struct{})
	var errs []error
	var stopping bool
	var panicked bool
	var panicVal any
	for runningTasks > 0 {
		c := <-completions
		runningTasks--

		if stopping {
			continue
		}

		if c.panicked {
			stopping = true
			panicked = true
			panicVal = c.panicVal
			continue
		}

		if c.err != nil {
			errs = append(errs, logOnce(ctx, c.err))
			switch mode {
			case FailureModeStop:
				stopping = true
				continue

			case FailureModeSkipDependents:
				var transitiveDependents []T
				transitiveDependents, err = graph.ReachableSet([]T{c.task}, func(t T) ([]T, error) {
					return dependents[t], nil
				})
				if err != nil {
					errs = append(errs, fmt.Errorf("cannot determine skipped tasks: %w", err))
				}

				for _, d := range transitiveDependents {
					if d == c.task {
						continue
					}

					skipped[d] = struct{}{}
				}
				continue
			}
		}

		if c.err == nil && c.resultSync != nil {
			err = c.resultSync()
			if err != nil {
				errs = append(errs, logOnce(ctx, err))
			}
		}

		for _, d := range dependents[c.task] {
			pendingDeps[d]--
			_, ok := skipped[d]
			if !ok && pendingDeps[d] == 0 {
				runningTasks++
				dispatchTask(ctx, activity, completions, run, d)
			}
		}
	}

	err = activity.Wait()
	if panicked {
		panic(panicVal)
	}
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func dispatchTask[T comparable](ctx context.Context, activity Activity, completions chan<- completion[T],
	run func(context.Context, T) (ResultSyncFunc, error), t T,
) {
	activity.Go(func(_ context.Context) error {
		c := completion[T]{
			task: t,
		}
		var returnedNormally bool
		defer func() {
			if !returnedNormally {
				c.panicked = true
				c.panicVal = recover()
			}
			completions <- c
		}()

		c.resultSync, c.err = run(ctx, t)
		returnedNormally = true

		return nil
	})
}
