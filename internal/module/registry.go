package module

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/gardenlinux/glci/internal/graph"
)

//nolint:gochecknoglobals // Required for automatic registration.
var typeSchemas = make(map[reflect.Type]any)

//nolint:gochecknoglobals // Cached reflect.Type for the marker interfaces.
var (
	anySlotType      = reflect.TypeFor[anySlot]()
	anySliceSlotType = reflect.TypeFor[anySliceSlot]()
)

// Category is the registry of implementations for a Module type T.
type Category[T Module] struct {
	ctors map[string]func(*Base) T
}

// NewCategory creates a Category.
func NewCategory[T Module]() *Category[T] {
	return &Category[T]{
		ctors: make(map[string]func(*Base) T),
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

	type config struct {
		Type string `mapstructure:"type"`
		ID   string `mapstructure:"id,omitzero"`
		//nolint:revive,nolintlint // The remain tag overrides the -, which is necessary to avoid an implicit name.
		Config map[string]any `mapstructure:"-,remain"`
	}
	var cfg config
	err := ParseConfig(rawCfg, &cfg)
	if err != nil {
		return zero, err
	}

	ctor, ok := cat.ctors[cfg.Type]
	if !ok {
		return zero, fmt.Errorf("unknown type %q", cfg.Type)
	}
	mod := ctor(b)

	if cfg.ID != "" {
		err = b.root.registerID(cfg.ID, mod)
		if err != nil {
			return zero, err
		}
	}

	err = mod.Configure(cfg.Config)
	if err != nil {
		return zero, fmt.Errorf("cannot configure type %q: %w", cfg.Type, err)
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

// RegisterSchema records the config schema for a Configurable, using a nil prototype (e.g. (*T)(nil)) and a zero-value config struct.
func RegisterSchema(prototype Configurable, schema any) {
	typeSchemas[reflect.TypeOf(prototype)] = schema
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

type schemaCollector struct {
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

// CollectSchemaKeys walks root's tree and returns dotted leaf keys for every reachable schema, with maxSliceLen keys per SliceSlot field.
func CollectSchemaKeys(root Configurable, maxSliceLen int) ([]string, error) {
	c := &schemaCollector{
		cache:       make(map[reflect.Type][]fieldEntry),
		path:        make(map[reflect.Type]struct{}),
		maxSliceLen: maxSliceLen,
	}
	c.walkType(reflect.TypeOf(root), "")
	return c.keys, c.err
}

func (c *schemaCollector) walkType(t reflect.Type, prefix string) {
	if c.err != nil {
		return
	}

	_, ok := c.path[t]
	if ok {
		c.err = fmt.Errorf("schema cycle: type %v reachable from itself at %q", t, prefix)
		return
	}

	var schema any
	schema, ok = typeSchemas[t]
	if !ok || schema == nil {
		return
	}

	c.path[t] = struct{}{}
	c.walkFields(schema, prefix)
	delete(c.path, t)
}

func (c *schemaCollector) walkFields(schema any, prefix string) {
	for _, f := range c.fieldEntries(schema) {
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

func (c *schemaCollector) fieldEntries(schema any) []fieldEntry {
	t := reflect.TypeOf(schema)
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

func (c *schemaCollector) walkSliceSlot(slotType reflect.Type, prefix string) {
	c.keys = append(c.keys, prefix+".id")
	for i := range c.maxSliceLen {
		c.walkSingleSlot(slotType, prefix+".items."+strconv.Itoa(i))
	}
}

func (c *schemaCollector) walkSingleSlot(slotType reflect.Type, prefix string) {
	switch slotType.Kind() {
	case reflect.Interface:
		c.walkCategory(slotType, prefix)
	case reflect.Pointer:
		c.walkType(slotType, prefix)
	}
}

func (c *schemaCollector) walkCategory(slotType reflect.Type, prefix string) {
	c.keys = append(c.keys, prefix+".type", prefix+".id")
	for typ := range typeSchemas {
		if !typ.Implements(slotType) {
			continue
		}

		c.walkType(typ, prefix)
	}
}
