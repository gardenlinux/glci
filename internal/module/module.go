package module

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync"

	"github.com/go-viper/mapstructure/v2"

	"github.com/gardenlinux/glci/internal/graph"
)

// Configurable is anything that can be configured from a raw config map and report nested configurables.
type Configurable interface {
	Configure(rawCfg map[string]any) error
	Configurables() []Configurable
}

// Module is a Configurable with a Start/Stop lifecycle.
type Module interface {
	Configurable

	Start(ctx context.Context) error
	Stop() error
}

// Base is the handle a Configurable holds (or embeds via Root) to participate in the module framework.
type Base struct {
	root *Root
}

// Root is embedded in the root Configurable and exposes root-only operations.
type Root struct {
	*Base

	self              Configurable
	namedModules      map[string]Module
	namedModuleSlices map[string][]Module
	startedModules    map[Module]int
	startedModulesMtx sync.Mutex
	refs              []refEntry
	configured        bool
}

type refEntry struct {
	owner   Configurable
	targets []Module
	resolve func(r *Root, modules []Module) ([]Module, error)
}

// NewRoot creates a Root.
func NewRoot(self Configurable) *Root {
	r := &Root{
		self:              self,
		namedModules:      make(map[string]Module),
		namedModuleSlices: make(map[string][]Module),
		startedModules:    make(map[Module]int),
	}
	r.Base = &Base{
		root: r,
	}
	return r
}

// Init recursively configures the module tree, resolves refs, and validates the dependency graph.
func (r *Root) Init(rawCfg map[string]any) error {
	err := r.self.Configure(rawCfg)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	var modules []Module
	modules, err = r.allModules()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	var refErrs []error
	for i := range r.refs {
		var targets []Module
		targets, err = r.refs[i].resolve(r, modules)
		if err != nil {
			refErrs = append(refErrs, err)
			continue
		}

		r.refs[i].targets = targets
	}
	if len(refErrs) > 0 {
		return fmt.Errorf("invalid configuration: %w", errors.Join(refErrs...))
	}

	err = r.checkCycles()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	r.configured = true

	return nil
}

func (r *Root) allModules() ([]Module, error) {
	configurables, err := graph.ReachableSet([]Configurable{r.self}, func(c Configurable) ([]Configurable, error) {
		return c.Configurables(), nil
	})
	if err != nil {
		return nil, wrapCycleErr(err, "ownership")
	}

	var modules []Module
	for _, c := range configurables {
		m, ok := c.(Module)
		if ok {
			modules = append(modules, m)
		}
	}

	return modules, nil
}

func (r *Root) checkCycles() error {
	_, err := graph.ReverseTopologicalSort([]Configurable{r.self}, r.dependencies())
	if err != nil {
		return wrapCycleErr(err, "reference")
	}

	return nil
}

func wrapCycleErr(err error, label string) error {
	cycleErr, ok := errors.AsType[*graph.CycleError[Configurable]](err)
	if !ok {
		return err
	}

	nodes := make([]string, 0, len(cycleErr.Cycle))
	for _, n := range cycleErr.Cycle {
		nodes = append(nodes, fmt.Sprintf("%T", n))
	}

	return fmt.Errorf("%s cycle: %v", label, nodes)
}

func (r *Root) dependencies() func(Configurable) ([]Configurable, error) {
	edges := make(map[Configurable][]Module)
	for _, ref := range r.refs {
		edges[ref.owner] = append(edges[ref.owner], ref.targets...)
	}

	return func(c Configurable) ([]Configurable, error) {
		deps := c.Configurables()
		for _, dep := range edges[c] {
			deps = append(deps, dep)
		}
		return deps, nil
	}
}

func (r *Root) registerID(id string, m Module) error {
	_, ok := r.namedModules[id]
	if ok {
		return fmt.Errorf("duplicate id %q", id)
	}

	_, ok = r.namedModuleSlices[id]
	if ok {
		return fmt.Errorf("duplicate id %q", id)
	}

	r.namedModules[id] = m
	return nil
}

func (r *Root) registerModuleSliceID(id string, s []Module) error {
	_, ok := r.namedModules[id]
	if ok {
		return fmt.Errorf("duplicate id %q", id)
	}

	_, ok = r.namedModuleSlices[id]
	if ok {
		return fmt.Errorf("duplicate id %q", id)
	}

	r.namedModuleSlices[id] = s
	return nil
}

// RegisterRef registers a reference to a single module identified by id.
func RegisterRef[T Module](b *Base, owner Configurable, ptr *T, id string) error {
	if b.root.configured {
		return errors.New("cannot register reference: base already configured")
	}

	b.root.refs = append(b.root.refs, refEntry{
		owner: owner,
		resolve: func(r *Root, _ []Module) ([]Module, error) {
			m, ok := r.namedModules[id]
			if !ok {
				return nil, fmt.Errorf("dangling ref to %q", id)
			}

			var t T
			t, ok = m.(T)
			if !ok {
				var zero T
				return nil, fmt.Errorf("module %q has wrong type, expected %T, got %T", id, zero, m)
			}

			*ptr = t

			return []Module{m}, nil
		},
	})

	return nil
}

// RegisterSliceRef registers a reference to a named slice of modules identified by id.
func RegisterSliceRef[T Module](b *Base, owner Configurable, ptr *[]T, id string) error {
	if b.root.configured {
		return errors.New("cannot register reference: base already configured")
	}

	b.root.refs = append(b.root.refs, refEntry{
		owner: owner,
		resolve: func(r *Root, _ []Module) ([]Module, error) {
			modules, ok := r.namedModuleSlices[id]
			if !ok {
				return nil, fmt.Errorf("dangling slice ref to %q", id)
			}

			typeModules := make([]T, 0, len(modules))
			var t T
			for i, m := range modules {
				t, ok = m.(T)
				if !ok {
					var zero T
					return nil, fmt.Errorf("slice %q element %d has wrong type, expected %T, got %T", id, i, zero, m)
				}

				typeModules = append(typeModules, t)
			}

			*ptr = typeModules

			return modules, nil
		},
	})

	return nil
}

// RegisterTypeRef registers a reference to the unique module satisfying T.
func RegisterTypeRef[T Module](b *Base, owner Configurable, ptr *T) error {
	if b.root.configured {
		return errors.New("cannot register reference: base already configured")
	}

	b.root.refs = append(b.root.refs, refEntry{
		owner: owner,
		resolve: func(_ *Root, modules []Module) ([]Module, error) {
			typeModules := filterByType[T](modules)
			var zero T
			if len(typeModules) == 0 {
				return nil, fmt.Errorf("no module of type %T", zero)
			}
			if len(typeModules) > 1 {
				return nil, fmt.Errorf("multiple modules of type %T", zero)
			}

			*ptr = typeModules[0]

			return []Module{typeModules[0]}, nil
		},
	})

	return nil
}

// RegisterSliceTypeRef registers a reference to every module satisfying T, in YAML appearance order.
func RegisterSliceTypeRef[T Module](b *Base, owner Configurable, ptr *[]T) error {
	if b.root.configured {
		return errors.New("cannot register reference: base already configured")
	}

	b.root.refs = append(b.root.refs, refEntry{
		owner: owner,
		resolve: func(_ *Root, modules []Module) ([]Module, error) {
			typeModules := filterByType[T](modules)

			*ptr = typeModules

			return AppendModules(nil, typeModules), nil
		},
	})

	return nil
}

func filterByType[T Module](modules []Module) []T {
	var typeModules []T
	for _, m := range modules {
		t, ok := m.(T)
		if ok {
			typeModules = append(typeModules, t)
		}
	}

	return typeModules
}

// AppendConfigurables appends each typed configurable to configurables.
func AppendConfigurables[T Configurable](configurables []Configurable, typedConfigurables []T) []Configurable {
	for _, c := range typedConfigurables {
		configurables = append(configurables, c)
	}

	return configurables
}

// AppendModules appends each typed module to modules.
func AppendModules[T Module](modules []Module, typedModules []T) []Module {
	for _, m := range typedModules {
		modules = append(modules, m)
	}

	return modules
}

// ParseConfig decodes a raw configuration map into a typed struct.
func ParseConfig[T any](rawCfg map[string]any, dst *T) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(decodeStringToInteger, decodeBareSliceSlot),
		Result:     dst,
	})
	if err != nil {
		return err
	}

	return decoder.Decode(rawCfg)
}

func decodeStringToInteger(from, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.String {
		return data, nil
	}

	str, ok := data.(string)
	if !ok {
		return data, nil
	}

	switch to.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.ParseInt(str, 10, 64)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.ParseUint(str, 10, 64)
	}

	return data, nil
}

func decodeBareSliceSlot(from, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.Slice {
		return data, nil
	}

	if !reflect.PointerTo(to).Implements(anySliceSlotType) {
		return data, nil
	}

	slot := reflect.New(to).Elem()
	items := slot.FieldByName("Items")
	if !items.IsValid() {
		return data, nil
	}

	bareSlice := reflect.ValueOf(data)
	itemsSlice := reflect.MakeSlice(items.Type(), bareSlice.Len(), bareSlice.Len())
	for i := range bareSlice.Len() {
		item := bareSlice.Index(i)
		if item.Kind() == reflect.Interface {
			item = item.Elem()
		}
		if !item.Type().AssignableTo(items.Type().Elem()) {
			return data, nil
		}
		itemsSlice.Index(i).Set(item)
	}
	items.Set(itemsSlice)

	return slot.Interface(), nil
}
