package main

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMain_(t *testing.T) {
	RegisterFailHandler(Fail)
	t.Parallel()
}
