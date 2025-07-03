package cloudprovider_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCloudProvider(t *testing.T) {
	RegisterFailHandler(Fail)
	t.Parallel()
}
