package module

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/graph"
	"github.com/gardenlinux/glci/internal/parallel"
)

// Start starts the modules reachable from targets. The returned stop function stops them.
func (r *Root) Start(ctx context.Context, targets ...Configurable) (func() error, error) {
	if !r.configured {
		return nil, errors.New("not configured")
	}

	r.startedModulesMtx.Lock()
	defer r.startedModulesMtx.Unlock()

	deps := r.dependencies()
	configurables, err := graph.ReverseTopologicalSort(targets, deps)
	if err != nil {
		return nil, wrapCycleErr(err, "dependency")
	}

	var modules []Module
	moduleDeps := make(map[Module][]Module)
	for _, c := range configurables {
		m, ok := c.(Module)
		if !ok {
			continue
		}

		modules = append(modules, m)

		var ns []Configurable
		ns, err = deps(m)
		if err != nil {
			return nil, fmt.Errorf("cannot get dependencies of %T: %w", m, err)
		}

		var d Module
		for _, n := range ns {
			d, ok = n.(Module)
			if ok {
				moduleDeps[m] = append(moduleDeps[m], d)
			}
		}
	}

	var started []Module
	err = parallel.RunTasksSync(ctx, modules, func(m Module) ([]Module, error) {
		return moduleDeps[m], nil
	}, func(ctx context.Context, m Module) (parallel.ResultSyncFunc, error) {
		if r.startedModules[m] != 0 {
			return nil, nil
		}

		inErr := m.Start(ctx)
		if inErr != nil {
			return nil, fmt.Errorf("cannot start %T: %w", m, inErr)
		}

		return func() error {
			started = append(started, m)

			return nil
		}, nil
	}, parallel.FailureModeSkipDependents)
	if err != nil {
		//nolint:contextcheck // Independent lifecycle, runs detached from parent ctx.
		stopErr := stop(started, moduleDeps)
		return nil, errors.Join(err, stopErr)
	}

	for _, m := range modules {
		r.startedModules[m]++
	}

	var stopped bool
	//nolint:contextcheck // Independent lifecycle, runs detached from parent ctx.
	return func() error {
		r.startedModulesMtx.Lock()
		defer r.startedModulesMtx.Unlock()

		if stopped {
			return nil
		}
		stopped = true

		var stoppable []Module
		for _, m := range modules {
			r.startedModules[m]--
			if r.startedModules[m] == 0 {
				delete(r.startedModules, m)
				stoppable = append(stoppable, m)
			}
		}

		return stop(stoppable, moduleDeps)
	}, nil
}

func stop(modules []Module, moduleDeps map[Module][]Module) error {
	stoppable := make(map[Module]struct{}, len(modules))
	for _, m := range modules {
		stoppable[m] = struct{}{}
	}

	stopAfter := make(map[Module][]Module)
	for _, m := range modules {
		for _, d := range moduleDeps[m] {
			_, ok := stoppable[d]
			if ok {
				stopAfter[d] = append(stopAfter[d], m)
			}
		}
	}

	return parallel.RunTasks(context.Background(), modules, func(m Module) ([]Module, error) {
		return stopAfter[m], nil
	}, func(_ context.Context, m Module) error {
		inErr := m.Stop()
		if inErr != nil {
			return fmt.Errorf("cannot stop %T: %w", m, inErr)
		}

		return nil
	}, parallel.FailureModeContinue)
}
