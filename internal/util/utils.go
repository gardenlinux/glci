package util

import (
	"context"
	"os"
	"slices"
	"strings"

	"github.com/gardenlinux/glci/internal/log"
)

// Ptr returns a pointer to any avlue, including a literal.
func Ptr[T any](t T) *T { return &t }

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

// CleanEnv unsets all environment variables that start with a given prefix.
func CleanEnv(ctx context.Context, prefix string) {
	for _, envVar := range os.Environ() {
		k, _, ok := strings.Cut(envVar, "=")
		if !ok {
			continue
		}
		if strings.HasPrefix(k, prefix) {
			log.Debug(ctx, "Unsetting environment variable", "var", k)
			_ = os.Unsetenv(k)
		}
	}
}
