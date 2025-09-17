package ptr

// P returns a pointer to any value, including a literal.
func P[T any](t T) *T { return &t }
