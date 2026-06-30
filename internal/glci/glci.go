package glci

import (
	"errors"
	"fmt"
	"maps"

	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/publisher"
)

// GLCI is the root of the module system and contains everything else.
type GLCI struct {
	*module.Root

	Publisher *publisher.Publisher
}

// New creates and configures a GLCI from raw configuration.
func New(rawCfg map[string]any) (*GLCI, error) {
	g := &GLCI{}
	g.Root = module.NewRoot(g)
	g.Publisher = publisher.NewPublisher(g.Base)
	err := g.Init(rawCfg)
	if err != nil {
		return nil, err
	}

	return g, nil
}

// Configure recursively configures a GLCI.
func (g *GLCI) Configure(rawCfg map[string]any) error {
	publishing, ok := rawCfg["publishing"].(map[string]any)
	if !ok {
		return errors.New("missing publishing")
	}

	var flavors any
	flavors, ok = rawCfg["flavors"]
	if !ok {
		return errors.New("missing flavors")
	}

	flatCfg := make(map[string]any, len(publishing)+2)
	maps.Copy(flatCfg, publishing)
	flatCfg["flavors"] = flavors

	var aliases any
	aliases, ok = rawCfg["aliases"]
	if ok {
		flatCfg["aliases"] = aliases
	}

	err := g.Publisher.Configure(flatCfg)
	if err != nil {
		return fmt.Errorf("cannot configure publisher: %w", err)
	}

	return nil
}

// Configurables returns configurable entities in support of the module system.
func (g *GLCI) Configurables() []module.Configurable {
	return []module.Configurable{g.Publisher}
}
