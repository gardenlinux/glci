package util

import (
	"encoding/hex"
	"hash"
	"os"
	"slices"
	"strings"
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
func CleanEnv(prefix string) {
	for _, envVar := range os.Environ() {
		k, _, ok := strings.Cut(envVar, "=")
		if !ok {
			continue
		}
		if strings.HasPrefix(k, prefix) {
			_ = os.Unsetenv(k)
		}
	}
}

// Hash returns a string hash of a string calculated using the provided hash function.
func Hash(h hash.Hash, str string) string {
	_, _ = h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(make([]byte, 0, h.Size())))
}
