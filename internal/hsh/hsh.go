package hsh

import (
	"encoding/hex"
	"hash"
)

// Hash returns a string hash of a string calculated using the provided hash function.
func Hash(h hash.Hash, str string) string {
	_, _ = h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(make([]byte, 0, h.Size())))
}
