package graph

import (
	"fmt"
	"slices"
)

// WalkTree visits each node in the acyclic tree rooted at root in the requested order. An error from children or visit aborts the walk.
func WalkTree[N any](root N, children func(N) ([]N, error), order Order, visit func(node N, depth int) error) error {
	type frame struct {
		node     N
		depth    int
		expanded bool
	}
	stack := []frame{{
		node:     root,
		depth:    0,
		expanded: false,
	}}

	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if f.expanded {
			err := visit(f.node, f.depth)
			if err != nil {
				return err
			}
			continue
		}

		switch order {
		case PreOrder:
			err := visit(f.node, f.depth)
			if err != nil {
				return err
			}
		case PostOrder:
			stack = append(stack, frame{
				node:     f.node,
				depth:    f.depth,
				expanded: true,
			})
		default:
			return fmt.Errorf("invalid order %d", order)
		}

		next, err := children(f.node)
		if err != nil {
			return err
		}

		for _, n := range slices.Backward(next) {
			stack = append(stack, frame{
				node:     n,
				depth:    f.depth + 1,
				expanded: false,
			})
		}
	}

	return nil
}
