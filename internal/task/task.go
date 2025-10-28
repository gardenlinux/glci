package task

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/go-viper/mapstructure/v2"

	"github.com/gardenlinux/glci/internal/log"
)

// StatePersistor is anything that can load and save task state.
type StatePersistor interface {
	Type() string
	SetCredentials(credentials map[string]any) error
	SetStateConfig(ctx context.Context, config any) error
	SetID(id string)
	Close() error
	Load() ([]byte, error)
	Save(state []byte) error
	Clear() error
}

// NewStatePersistor returns a new StatePersistor of a given type.
func NewStatePersistor(typ string) (StatePersistor, error) {
	nf, ok := persistors[typ]
	if !ok {
		return nil, fmt.Errorf("state persistor %s is not supported", typ)
	}

	return nf(), nil
}

// RollbackHandler is anything that can roll back task state.
type RollbackHandler interface {
	CanRollback() string
	Rollback(ctx context.Context, tasks map[string]Task) error
}

// Task is an ongoing task that can be rolled back.
type Task struct {
	State     State  `json:"state,omitempty"`
	Error     string `json:"error,omitzero"`
	batch     string
	completed bool
}

// State is the current state of an ongoing task.
type State any

// WithStatePersistor stores a StatePersistor into the context.
func WithStatePersistor(ctx context.Context, persistor StatePersistor, id string) context.Context {
	persistor.SetID(id)

	log.Debug(ctx, "Loading state", "persistor", persistor.Type())
	state, err := persistor.Load()
	if err != nil {
		return ctx
	}

	tset := &taskSet{
		persistor: persistor,
	}
	if state != nil {
		err = json.Unmarshal(state, &tset.domains)
		if err != nil {
			return ctx
		}
	}
	if tset.domains == nil {
		tset.domains = make(map[string]taskDomain)
	}

	return context.WithValue(ctx, ctxkSet{}, tset)
}

// WithDomain stores a domain into the context.
func WithDomain(ctx context.Context, domain string) context.Context {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil {
		return ctx
	}

	func() {
		tset.mtx.Lock()
		defer tset.mtx.Unlock()

		if tset.domains[domain].Tasks == nil {
			tset.domains[domain] = taskDomain{
				Tasks: make(map[string]Task),
			}
		}
	}()

	return context.WithValue(ctx, ctxkDomain{}, domain)
}

// WithBatch stores a batch into the context.
func WithBatch(ctx context.Context, batch string) context.Context {
	return context.WithValue(ctx, ctxkBatch{}, batch)
}

// WithUndeadMode stores an undead mode into the context.
func WithUndeadMode(ctx context.Context, undead bool) context.Context {
	return context.WithValue(ctx, ctxkUndead{}, undead)
}

// Begin begins a new task with an initial state and associates it to the context.
func Begin[STATE any](ctx context.Context, id string, state STATE) context.Context {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil {
		return ctx
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)
	batch, _ := ctx.Value(ctxkBatch{}).(string)
	func() {
		tset.mtx.Lock()
		defer tset.mtx.Unlock()

		tset.domains[domain].Tasks[id] = Task{
			State: state,
			batch: batch,
		}

		saveState(ctx, tset)
	}()

	return context.WithValue(ctx, ctxkTask{}, id)
}

// Update updates the state task associated with the context.
func Update[STATE any](ctx context.Context, update func(STATE) STATE) {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil || tset.domains == nil {
		return
	}

	id, _ := ctx.Value(ctxkTask{}).(string)
	if id == "" {
		return
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)

	tset.mtx.Lock()
	defer tset.mtx.Unlock()

	task, ok := tset.domains[domain].Tasks[id]
	if !ok {
		return
	}

	var state STATE
	state, ok = task.State.(STATE)
	if !ok {
		return
	}

	task.State = update(state)
	tset.domains[domain].Tasks[id] = task

	saveState(ctx, tset)
}

// Complete either deletes or marks as completed the task associated with the context.
func Complete(ctx context.Context) {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil || tset.domains == nil {
		return
	}

	id, _ := ctx.Value(ctxkTask{}).(string)
	if id == "" {
		return
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)
	undead, _ := ctx.Value(ctxkUndead{}).(bool)

	tset.mtx.Lock()
	defer tset.mtx.Unlock()

	if undead {
		task, ok := tset.domains[domain].Tasks[id]
		if !ok {
			return
		}
		task.completed = true
		tset.domains[domain].Tasks[id] = task
	} else {
		delete(tset.domains[domain].Tasks, id)
		if len(tset.domains[domain].Tasks) == 0 {
			delete(tset.domains, domain)
		}
	}

	saveState(ctx, tset)
}

// Fail sets an error into the task associated with the context.
func Fail(ctx context.Context, err error) error {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil || tset.domains == nil {
		return err
	}

	id, _ := ctx.Value(ctxkTask{}).(string)
	if id == "" {
		return err
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)

	task, ok := tset.domains[domain].Tasks[id]
	if !ok {
		return err
	}

	task.Error = err.Error()
	tset.domains[domain].Tasks[id] = task

	saveState(ctx, tset)
	return err
}

// RemoveCompleted removes all completed tasks within a batch.
func RemoveCompleted(ctx context.Context, batch string) {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil || tset.domains == nil {
		return
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)

	tset.mtx.Lock()
	defer tset.mtx.Unlock()

	for id, task := range tset.domains[domain].Tasks {
		if task.batch == batch && task.completed {
			delete(tset.domains[domain].Tasks, id)
			if len(tset.domains[domain].Tasks) == 0 {
				delete(tset.domains, domain)
			}
		}
	}

	saveState(ctx, tset)
}

// Clear removes all state from the persistor.
func Clear(ctx context.Context) {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil || tset.persistor == nil {
		return
	}

	tset.mtx.Lock()
	defer tset.mtx.Unlock()

	tset.domains = nil
	log.Debug(ctx, "Clearing state", "persistor", tset.persistor.Type())
	err := tset.persistor.Clear()
	if err != nil {
		tset.persistorErr = fmt.Errorf("cannot clear state: %w", err)
	}
}

// PersistorError returns any error that the StatePersistor associated with the context may have set.
func PersistorError(ctx context.Context) error {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil {
		return errors.New("missing state")
	}

	tset.mtx.Lock()
	defer tset.mtx.Unlock()

	return tset.persistorErr
}

// Rollback dispatches ongoing tasks to a set of handlers to roll back based on domains.
func Rollback(ctx context.Context, handlers []RollbackHandler) error {
	tset, _ := ctx.Value(ctxkSet{}).(*taskSet)
	if tset == nil {
		return errors.New("missing state")
	}

	domainHandlers := make(map[string]RollbackHandler, len(handlers))
	for _, handler := range handlers {
		domain := handler.CanRollback()
		_, ok := domainHandlers[domain]
		if ok {
			return fmt.Errorf("duplicate handler for domain %s", domain)
		}
		domainHandlers[domain] = handler
	}

	tset.mtx.Lock()
	defer tset.mtx.Unlock()

	if tset.persistorErr != nil {
		return fmt.Errorf("invalid state due to persistor error: %w", tset.persistorErr)
	}

	cnt := 0
	for domain, tasks := range tset.domains {
		handler, ok := domainHandlers[domain]
		if !ok {
			return fmt.Errorf("invalid task domain %s", domain)
		}
		lctx := log.WithValues(ctx, "domain", domain)

		if len(tasks.Tasks) > 0 {
			cnt += len(tasks.Tasks)
			log.Info(lctx, "Rolling back incomplete tasks", "tasks", len(tasks.Tasks))
			err := handler.Rollback(lctx, tasks.Tasks)
			if err != nil {
				return fmt.Errorf("cannot roll back tasks for domain %s: %w", domain, err)
			}
		}

		delete(tset.domains, domain)
	}
	saveState(ctx, tset)

	if cnt > 0 {
		log.Info(ctx, "Rollback completed successfully", "count", cnt)
	}
	return nil
}

// ParseState converts generic task state into a specific type.
func ParseState[STATE any](generic State) (STATE, error) {
	var state STATE

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &state,
		TagName: "json",
	})
	if err != nil {
		return state, fmt.Errorf("invalid task state: %w", err)
	}
	err = decoder.Decode(generic)
	if err != nil {
		return state, fmt.Errorf("invalid task state: %w", err)
	}

	return state, nil
}

//nolint:gochecknoglobals // Required for automatic registration.
var (
	persistors = make(map[string]newStatePersistorFunc)
)

type (
	ctxkBatch  struct{}
	ctxkDomain struct{}
	ctxkSet    struct{}
	ctxkTask   struct{}
	ctxkUndead struct{}
)

type taskSet struct {
	domains      map[string]taskDomain
	mtx          sync.Mutex
	persistor    StatePersistor
	persistorErr error
}

type taskDomain struct {
	Tasks map[string]Task `json:"tasks,omitempty"`
}

type newStatePersistorFunc func() StatePersistor

func registerStatePersistor(nf newStatePersistorFunc) {
	persistors[nf().Type()] = nf
}

func setCredentials[CREDS any](allCreds map[string]any, section string, creds *map[string]CREDS) error {
	rawCreds, ok := allCreds[section]
	if !ok {
		return errors.New("missing credentials")
	}

	var sCreds map[string]any
	sCreds, ok = rawCreds.(map[string]any)
	if !ok {
		return errors.New("invalid credentials")
	}

	if *creds == nil {
		*creds = make(map[string]CREDS, len(sCreds))
	}

	for configuration, cCreds := range sCreds {
		var c CREDS
		err := mapstructure.Decode(cCreds, &c)
		if err != nil {
			return fmt.Errorf("invalid credentials for configuration %s: %w", configuration, err)
		}

		(*creds)[configuration] = c
	}

	return nil
}

func setConfig[CONFIG any](cfg any, config *CONFIG) error {
	err := mapstructure.Decode(cfg, &config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return nil
}

func saveState(ctx context.Context, tset *taskSet) {
	if tset.persistor == nil {
		return
	}

	state, err := json.Marshal(tset.domains)
	if err != nil {
		tset.persistorErr = fmt.Errorf("cannot serialize state: %w", err)
		return
	}

	log.Debug(ctx, "Saving state", "persistor", tset.persistor.Type())
	err = tset.persistor.Save(state)
	if err != nil {
		tset.persistorErr = fmt.Errorf("cannot save state: %w", err)
		return
	}
}
