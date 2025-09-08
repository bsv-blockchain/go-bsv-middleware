package testabilities

import (
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities"
)

type ServerFixture = testabilities.ServerFixture
type MiddlewareFixture = testabilities.MiddlewareFixture

type RegressionTestFixture interface {
	Server() ServerFixture
	Middleware() MiddlewareFixture
}

func Given(t testing.TB) RegressionTestFixture {
	f := testabilities.Given(t)
	return f
}
