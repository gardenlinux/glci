package ptr

// P returns a pointer to any avlue, including a literal.
func P[T any](t T) *T { return &t }
