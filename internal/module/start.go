package module

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

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
	done := make(map[Module]chan struct{})
	failed := make(map[Module]*atomic.Bool)
	moduleDeps := make(map[Module][]Module)
	for _, c := range configurables {
		m, ok := c.(Module)
		if !ok {
			continue
		}

		modules = append(modules, m)
		done[m] = make(chan struct{})
		failed[m] = &atomic.Bool{}

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
	startActivity := parallel.NewActivitySync(ctx)

	for _, m := range modules {
		startActivity.Go(func(_ context.Context) (parallel.ResultFunc, error) {
			defer close(done[m])

			if r.startedModules[m] != 0 {
				return nil, nil
			}

			for _, dependency := range moduleDeps[m] {
				<-done[dependency]
				if failed[dependency].Load() {
					failed[m].Store(true)
					return nil, nil
				}
			}

			startErr := m.Start(ctx)
			if startErr != nil {
				failed[m].Store(true)
				return nil, fmt.Errorf("cannot start %T: %w", m, startErr)
			}

			return func() error {
				started = append(started, m)

				return nil
			}, nil
		})
	}

	startErr := startActivity.Wait()
	if startErr != nil {
		//nolint:contextcheck // Independent lifecycle, runs detached from parent ctx.
		stopErr := stop(started, moduleDeps)
		return nil, errors.Join(startErr, stopErr)
	}

	for _, m := range modules {
		r.startedModules[m]++
	}

	stopped := false
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
	if len(modules) == 0 {
		return nil
	}

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

	done := make(map[Module]chan struct{}, len(modules))
	for _, m := range modules {
		done[m] = make(chan struct{})
	}
	stopActivity := parallel.NewActivity(context.Background())

	for _, m := range modules {
		stopActivity.Go(func(_ context.Context) error {
			defer close(done[m])
			for _, dependent := range stopAfter[m] {
				<-done[dependent]
			}

			stopErr := m.Stop()
			if stopErr != nil {
				return fmt.Errorf("cannot stop %T: %w", m, stopErr)
			}

			return nil
		})
	}

	return stopActivity.Wait()
}
