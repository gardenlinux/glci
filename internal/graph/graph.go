package graph

// Order is the visit order for graph algorithms.
type Order int

const (
	// PreOrder visits each node before its children.
	PreOrder Order = iota + 1
	// PostOrder visits each node after its children.
	PostOrder
)

// Cycles controls how DFS reacts to a back-edge, an edge to a node already on the current path.
type Cycles int

const (
	// CyclesAllow makes DFS skip a back-edge and continue the walk.
	CyclesAllow Cycles = iota + 1
	// CyclesError makes DFS return a *CycleError on any back-edge.
	CyclesError
)
