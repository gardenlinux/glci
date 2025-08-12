package env

import (
	"os"
	"strings"
)

// Clean unsets all environment variables that start with a given prefix.
func Clean(prefix string) {
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
