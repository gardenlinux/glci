package module

import (
	"fmt"
	"maps"
	"reflect"
	"strconv"
	"strings"

	"github.com/gardenlinux/glci/internal/graph"
)

//nolint:gochecknoglobals // Required for automatic registration.
var (
	configTypes  = make(map[reflect.Type]any)
	selectorKeys = make(map[reflect.Type]string)
)

//nolint:gochecknoglobals // Cached reflect.Type for the marker interfaces.
var (
	anySlotType      = reflect.TypeFor[anySlot]()
	anySliceSlotType = reflect.TypeFor[anySliceSlot]()
)

// Category is the registry of implementations for a Module type T.
type Category[T Module] struct {
	selectorKey string
	ctors       map[string]func(*Base) T
}

// NewCategory creates a Category whose implementations are selected by the value under selectorKey.
func NewCategory[T Module](selectorKey string) *Category[T] {
	selectorKeys[reflect.TypeFor[T]()] = selectorKey

	return &Category[T]{
		selectorKey: selectorKey,
		ctors:       make(map[string]func(*Base) T),
	}
}

// RegisterImpl registers an implementation for typ in cat.
func RegisterImpl[T Module](cat *Category[T], typ string, ctor func(*Base) T) {
	cat.ctors[typ] = ctor
}

// ConfigureModule decodes, instantiates, registers, and configures a module.
func ConfigureModule[T Module](b *Base, cat *Category[T], rawCfg map[string]any) (T, error) {
	return configureModule(b, cat, rawCfg)
}

// ConfigureModules decodes, instantiates, registers, and configures every member of a SliceSlot.
func ConfigureModules[T Module](b *Base, cat *Category[T], slot SliceSlot[T]) ([]T, error) {
	mods := make([]T, 0, len(slot.Items))
	slice := make([]Module, 0, len(slot.Items))
	for _, rawCfg := range slot.Items {
		mod, err := configureModule(b, cat, rawCfg)
		if err != nil {
			return nil, err
		}

		mods = append(mods, mod)
		slice = append(slice, mod)
	}

	if slot.ID != "" {
		err := b.root.registerModuleSliceID(slot.ID, slice)
		if err != nil {
			return nil, err
		}
	}

	return mods, nil
}

func configureModule[T Module](b *Base, cat *Category[T], rawCfg map[string]any) (T, error) {
	var zero T

	typ, _ := rawCfg[cat.selectorKey].(string)
	if typ == "" {
		return zero, fmt.Errorf("missing %q", cat.selectorKey)
	}

	rawCfg = maps.Clone(rawCfg)
	delete(rawCfg, cat.selectorKey)

	type config struct {
		ID string `mapstructure:"id,omitzero"`
		//nolint:revive,nolintlint // The remain tag overrides the -, which is necessary to avoid an implicit name.
		Config map[string]any `mapstructure:"-,remain"`
	}
	var cfg config
	err := ParseConfig(rawCfg, &cfg)
	if err != nil {
		return zero, err
	}

	ctor, ok := cat.ctors[typ]
	if !ok {
		return zero, fmt.Errorf("unknown type %q", typ)
	}
	mod := ctor(&Base{
		root: b.root,
		id:   cfg.ID,
	})

	if cfg.ID != "" {
		err = b.root.registerID(cfg.ID, mod)
		if err != nil {
			return zero, err
		}
	}

	err = mod.Configure(cfg.Config)
	if err != nil {
		return zero, fmt.Errorf("cannot configure type %q: %w", typ, err)
	}

	return mod, nil
}

// Slot is a config field that hosts another Configurable. T is either a category interface or a concrete *Type.
type Slot[T any] map[string]any

func (Slot[T]) slotType() reflect.Type {
	return reflect.TypeFor[T]()
}

type anySlot interface {
	slotType() reflect.Type
}

// SliceSlot is a config field that hosts a named list of Configurables. T is either a category interface or a concrete *Type.
type SliceSlot[T any] struct {
	ID    string           `mapstructure:"id,omitzero"`
	Items []map[string]any `mapstructure:"items"`
}

func (SliceSlot[T]) sliceSlotType() reflect.Type {
	return reflect.TypeFor[T]()
}

type anySliceSlot interface {
	sliceSlotType() reflect.Type
}

// RegisterConfigType records the config type for a Configurable, called with a nil impl (e.g. (*T)(nil)) and a zero-value config struct.
func RegisterConfigType(impl Configurable, config any) {
	configTypes[reflect.TypeOf(impl)] = config
}

// MaxSliceLen returns the longest slice length found anywhere in cfg.
func MaxSliceLen(rawCfg any) int {
	var maxLen int
	_ = graph.WalkTree(rawCfg, func(n any) ([]any, error) {
		switch v := n.(type) {
		case map[string]any:
			children := make([]any, 0, len(v))
			for _, child := range v {
				children = append(children, child)
			}

			return children, nil

		case []any:
			return v, nil
		}

		return nil, nil
	}, graph.PreOrder, func(n any, _ int) error {
		slice, ok := n.([]any)
		if ok && len(slice) > maxLen {
			maxLen = len(slice)
		}

		return nil
	})

	return maxLen
}

type keyCollector struct {
	cache       map[reflect.Type][]fieldEntry
	path        map[reflect.Type]struct{}
	keys        []string
	maxSliceLen int
	err         error
}

type fieldEntry struct {
	name     string
	slotType reflect.Type
	slice    bool
}

// ConfigKeys walks root's tree and returns dotted leaf keys for every reachable config type, with maxSliceLen keys per SliceSlot field.
func ConfigKeys(root Configurable, maxSliceLen int) ([]string, error) {
	c := &keyCollector{
		cache:       make(map[reflect.Type][]fieldEntry),
		path:        make(map[reflect.Type]struct{}),
		maxSliceLen: maxSliceLen,
	}
	c.walkType(reflect.TypeOf(root), "")
	return c.keys, c.err
}

func (c *keyCollector) walkType(t reflect.Type, prefix string) {
	if c.err != nil {
		return
	}

	_, ok := c.path[t]
	if ok {
		c.err = fmt.Errorf("config type cycle: type %v reachable from itself at %q", t, prefix)
		return
	}

	var configType any
	configType, ok = configTypes[t]
	if !ok || configType == nil {
		return
	}

	c.path[t] = struct{}{}
	c.walkFields(configType, prefix)
	delete(c.path, t)
}

func (c *keyCollector) walkFields(configType any, prefix string) {
	for _, f := range c.fieldEntries(configType) {
		field := f.name
		if prefix != "" {
			field = prefix + "." + f.name
		}

		if f.slotType == nil {
			c.keys = append(c.keys, field)
			continue
		}

		if f.slice {
			c.walkSliceSlot(f.slotType, field)
		} else {
			c.walkSingleSlot(f.slotType, field)
		}
	}
}

func (c *keyCollector) fieldEntries(configType any) []fieldEntry {
	t := reflect.TypeOf(configType)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	cached, ok := c.cache[t]
	if ok {
		return cached
	}

	var entries []fieldEntry
	for _, f := range reflect.VisibleFields(t) {
		tag := f.Tag.Get("mapstructure")
		if tag == "" {
			continue
		}

		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}

		var slot anySlot
		var sliceSlot anySliceSlot
		entry := fieldEntry{
			name: name,
		}
		switch {
		case f.Type.Implements(anySlotType):
			slot, ok = reflect.New(f.Type).Elem().Interface().(anySlot)
			if !ok {
				continue
			}
			entry.slotType = slot.slotType()

		case f.Type.Implements(anySliceSlotType):
			sliceSlot, ok = reflect.New(f.Type).Elem().Interface().(anySliceSlot)
			if !ok {
				continue
			}
			entry.slotType = sliceSlot.sliceSlotType()
			entry.slice = true
		}
		entries = append(entries, entry)
	}
	c.cache[t] = entries

	return entries
}

func (c *keyCollector) walkSliceSlot(slotType reflect.Type, prefix string) {
	c.keys = append(c.keys, prefix+".id")
	for i := range c.maxSliceLen {
		c.walkSingleSlot(slotType, prefix+".items."+strconv.Itoa(i))
	}
}

func (c *keyCollector) walkSingleSlot(slotType reflect.Type, prefix string) {
	switch slotType.Kind() {
	case reflect.Interface:
		c.walkCategory(slotType, prefix)
	case reflect.Pointer:
		c.walkType(slotType, prefix)
	}
}

func (c *keyCollector) walkCategory(slotType reflect.Type, prefix string) {
	if c.err != nil {
		return
	}

	selectorKey, ok := selectorKeys[slotType]
	if !ok {
		c.err = fmt.Errorf("category at config key %q not registered", prefix)
		return
	}
	if selectorKey == "" {
		c.err = fmt.Errorf("category at config key %q has no selector key", prefix)
		return
	}

	c.keys = append(c.keys, prefix+"."+selectorKey, prefix+".id")
	for typ := range configTypes {
		if !typ.Implements(slotType) {
			continue
		}

		c.walkType(typ, prefix)
	}
}
