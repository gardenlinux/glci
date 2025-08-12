package slc

import (
	"slices"
)

// Subset returns a subset of a slice.
func Subset[T comparable](original, subset []T) []T {
	res := make([]T, 0, min(len(original), len(subset)))
	for _, e := range original {
		if slices.Contains(subset, e) {
			res = append(res, e)
		}
	}
	return res
}
