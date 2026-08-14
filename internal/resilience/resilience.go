package resilience

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/go-viper/mapstructure/v2"

	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
)

type (
	ctxkBatch     struct{}
	ctxkDomain    struct{}
	ctxkSet       struct{}
	ctxkOperation struct{}
	ctxkUndead    struct{}
)

// Category is the module framework registry for StatePersistor implementations.
//
//nolint:gochecknoglobals // Required for automatic registration.
var Category = module.NewCategory[StatePersistor]("backend")

// StatePersistor is anything that can load and save operation state.
type StatePersistor interface {
	module.Module

	Type() string
	SetID(id string)
	Load() ([]byte, error)
	Save(state []byte) error
	Clear() error
}

type operationSet struct {
	domains      map[string]operationDomain
	mtx          sync.Mutex
	persistor    StatePersistor
	persistorErr error
}

type operationDomain struct {
	Operations map[string]Operation `json:"operations,omitempty"`
}

// WithStatePersistor stores a StatePersistor into the context.
func WithStatePersistor(ctx context.Context, persistor StatePersistor, id string) context.Context {
	persistor.SetID(id)

	log.Debug(ctx, "Loading state", "persistor", persistor.Type())
	state, err := persistor.Load()
	if err != nil {
		return ctx
	}

	opset := &operationSet{
		persistor: persistor,
	}
	if state != nil {
		err = json.Unmarshal(state, &opset.domains)
		if err != nil {
			return ctx
		}
	}
	if opset.domains == nil {
		opset.domains = make(map[string]operationDomain)
	}

	return context.WithValue(ctx, ctxkSet{}, opset)
}

// WithDomain stores a domain into the context.
func WithDomain(ctx context.Context, domain string) context.Context {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil {
		return ctx
	}

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	if opset.domains == nil {
		return ctx
	}

	if opset.domains[domain].Operations == nil {
		opset.domains[domain] = operationDomain{
			Operations: make(map[string]Operation),
		}
	}

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

// Operation is an ongoing operation that can be rolled back.
type Operation struct {
	State     OperationState `json:"state,omitzero"`
	Error     string         `json:"error,omitzero"`
	batch     string
	completed bool
}

// OperationState is the current state of an ongoing operation.
type OperationState any

// BeginOperation begins a new operation with an initial state and associates it to the context.
func BeginOperation[STATE any](ctx context.Context, id string, state STATE) context.Context {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil {
		return ctx
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)
	batch, _ := ctx.Value(ctxkBatch{}).(string)

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	if opset.domains == nil {
		return ctx
	}

	opset.domains[domain].Operations[id] = Operation{
		State: state,
		batch: batch,
	}

	saveState(ctx, opset)

	return context.WithValue(ctx, ctxkOperation{}, id)
}

// UpdateOperation updates the state of the operation associated with the context.
func UpdateOperation[STATE any](ctx context.Context, update func(STATE) STATE) {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil {
		return
	}

	id, _ := ctx.Value(ctxkOperation{}).(string)
	if id == "" {
		return
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	if opset.domains == nil {
		return
	}

	op, ok := opset.domains[domain].Operations[id]
	if !ok {
		return
	}

	var state STATE
	state, ok = op.State.(STATE)
	if !ok {
		return
	}

	op.State = update(state)
	opset.domains[domain].Operations[id] = op

	saveState(ctx, opset)
}

// CompleteOperation either deletes or marks as completed the operation associated with the context.
func CompleteOperation(ctx context.Context) {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil {
		return
	}

	id, _ := ctx.Value(ctxkOperation{}).(string)
	if id == "" {
		return
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)
	undead, _ := ctx.Value(ctxkUndead{}).(bool)

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	if opset.domains == nil {
		return
	}

	if undead {
		op, ok := opset.domains[domain].Operations[id]
		if !ok {
			return
		}
		op.completed = true
		opset.domains[domain].Operations[id] = op
	} else {
		delete(opset.domains[domain].Operations, id)
		if len(opset.domains[domain].Operations) == 0 {
			delete(opset.domains, domain)
		}
	}

	saveState(ctx, opset)
}

// FailOperation sets an error into the operation associated with the context.
func FailOperation(ctx context.Context, err error) error {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil {
		return err
	}

	id, _ := ctx.Value(ctxkOperation{}).(string)
	if id == "" {
		return err
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	if opset.domains == nil {
		return err
	}

	op, ok := opset.domains[domain].Operations[id]
	if !ok {
		return err
	}

	op.Error = err.Error()
	opset.domains[domain].Operations[id] = op

	saveState(ctx, opset)
	return err
}

// RemoveCompletedOperations removes all completed operations within a batch.
func RemoveCompletedOperations(ctx context.Context, batch string) {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil {
		return
	}

	domain, _ := ctx.Value(ctxkDomain{}).(string)

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	if opset.domains == nil {
		return
	}

	for id, op := range opset.domains[domain].Operations {
		if op.batch == batch && op.completed {
			delete(opset.domains[domain].Operations, id)
			if len(opset.domains[domain].Operations) == 0 {
				delete(opset.domains, domain)
			}
		}
	}

	saveState(ctx, opset)
}

func saveState(ctx context.Context, opset *operationSet) {
	if opset.persistor == nil {
		return
	}

	state, err := json.Marshal(opset.domains)
	if err != nil {
		opset.persistorErr = fmt.Errorf("cannot serialize state: %w", err)
		return
	}

	log.Debug(ctx, "Saving state", "persistor", opset.persistor.Type())
	err = opset.persistor.Save(state)
	if err != nil {
		opset.persistorErr = fmt.Errorf("cannot save state: %w", err)
		return
	}
}

// ClearState removes all state from the persistor.
func ClearState(ctx context.Context) {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil || opset.persistor == nil {
		return
	}

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	opset.domains = nil
	log.Debug(ctx, "Clearing state", "persistor", opset.persistor.Type())
	err := opset.persistor.Clear()
	if err != nil {
		opset.persistorErr = fmt.Errorf("cannot clear state: %w", err)
	}
}

// PersistorError returns any error that the StatePersistor associated with the context may have set.
func PersistorError(ctx context.Context) error {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil {
		return errors.New("missing state")
	}

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	return opset.persistorErr
}

// ParseOperationState converts generic operation state into a specific type.
func ParseOperationState[STATE any](generic OperationState) (STATE, error) {
	var state STATE

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &state,
		TagName: "json",
	})
	if err != nil {
		return state, fmt.Errorf("invalid operation state: %w", err)
	}
	err = decoder.Decode(generic)
	if err != nil {
		return state, fmt.Errorf("invalid operation state: %w", err)
	}

	return state, nil
}

// RollbackHandler is anything that can roll back operation state.
type RollbackHandler interface {
	RollbackDomain() string
	Rollback(ctx context.Context, operations map[string]Operation) error
}

// Rollback dispatches ongoing operations to a set of handlers to roll back based on domains.
func Rollback(ctx context.Context, handlers []RollbackHandler) error {
	opset, _ := ctx.Value(ctxkSet{}).(*operationSet)
	if opset == nil {
		return errors.New("missing state")
	}

	domainHandlers := make(map[string]RollbackHandler, len(handlers))
	for _, handler := range handlers {
		domain := handler.RollbackDomain()
		_, ok := domainHandlers[domain]
		if ok {
			return fmt.Errorf("duplicate handler for domain %s", domain)
		}
		domainHandlers[domain] = handler
	}

	opset.mtx.Lock()
	defer opset.mtx.Unlock()

	if opset.persistorErr != nil {
		return fmt.Errorf("invalid state due to persistor error: %w", opset.persistorErr)
	}

	cnt := 0
	rollbackDomains := concurrency.NewActivitySync(ctx)
	for domain, ops := range opset.domains {
		handler, ok := domainHandlers[domain]
		if !ok {
			return fmt.Errorf("invalid operation domain %s", domain)
		}

		rollbackDomains.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			rf := func() error {
				cnt += len(opset.domains[domain].Operations)
				delete(opset.domains, domain)

				return nil
			}

			if len(ops.Operations) == 0 {
				return rf, nil
			}
			ctx = log.WithValues(ctx, "domain", domain)

			log.Info(ctx, "Rolling back incomplete operations", "operations", len(ops.Operations))
			err := handler.Rollback(ctx, ops.Operations)
			if err != nil {
				return nil, fmt.Errorf("cannot roll back operations for domain %s: %w", domain, err)
			}

			return rf, nil
		})
	}
	err := rollbackDomains.Wait()
	if err != nil {
		return err
	}

	saveState(ctx, opset)

	if cnt > 0 {
		log.Info(ctx, "Rollback completed successfully", "count", cnt)
	}
	return nil
}

func parseConfig[CONFIG any](cfg map[string]any, config *CONFIG) error {
	err := mapstructure.Decode(cfg, &config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return nil
}

func parseCredentials[CREDS any](rawCreds map[string]any, creds *CREDS) error {
	err := mapstructure.Decode(rawCreds, creds)
	if err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}

	return nil
}
