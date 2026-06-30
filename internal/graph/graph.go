package graph

// Order is the visit order for graph algorithms.
type Order int

const (
	// PreOrder visits each node before its children.
	PreOrder Order = iota + 1
	// PostOrder visits each node after its children.
	PostOrder
)
