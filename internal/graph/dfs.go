package graph

import (
	"fmt"
	"slices"
)

// CycleError indicates that a graph contains a cycle.
type CycleError[N comparable] struct {
	Cycle []N
}

func (e *CycleError[N]) Error() string {
	return fmt.Sprintf("cycle detected: %v", e.Cycle)
}

// ReverseTopologicalSort runs DFS from each root and returns the nodes in reverse topological order or *CycleError if there is a cycle.
func ReverseTopologicalSort[N comparable](roots []N, neighbors func(N) ([]N, error)) ([]N, error) {
	return DFS(roots, neighbors, PostOrder)
}

// ReachableSet runs DFS from each root and returns every reachable node in pre-order or *CycleError if there is a cycle.
func ReachableSet[N comparable](roots []N, neighbors func(N) ([]N, error)) ([]N, error) {
	return DFS(roots, neighbors, PreOrder)
}

// DFS runs depth-first search from each root and returns the visited nodes in the requested order or *CycleError if there is a cycle.
func DFS[N comparable](roots []N, neighbors func(N) ([]N, error), order Order) ([]N, error) {
	const (
		white = 0
		gray  = 1
		black = 2
	)

	type frame struct {
		node     N
		expanded bool
	}

	color := make(map[N]int)
	var path []N
	var visited []N
	var stack []frame

	for _, r := range slices.Backward(roots) {
		stack = append(stack, frame{
			node:     r,
			expanded: true,
		})
	}

	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if !f.expanded {
			path = path[:len(path)-1]
			color[f.node] = black
			if order == PostOrder {
				visited = append(visited, f.node)
			}

			continue
		}

		c := color[f.node]
		if c == gray {
			start := slices.Index(path, f.node)
			return nil, &CycleError[N]{
				Cycle: append([]N(nil), path[start:]...),
			}
		}
		if c == black {
			continue
		}

		color[f.node] = gray
		if order == PreOrder {
			visited = append(visited, f.node)
		}
		path = append(path, f.node)
		stack = append(stack, frame{
			node:     f.node,
			expanded: false,
		})

		next, err := neighbors(f.node)
		if err != nil {
			return nil, err
		}
		for _, n := range slices.Backward(next) {
			stack = append(stack, frame{
				node:     n,
				expanded: true,
			})
		}
	}

	return visited, nil
}
