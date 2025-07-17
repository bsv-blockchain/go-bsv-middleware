package testabilities

import (
	"testing"
)

type RegressionTestFixture interface {
	Server() ServerFixture
	Middleware() MiddlewareFixture
}

type regressionTestFixture struct {
	testing.TB
}

func Given(t testing.TB) RegressionTestFixture {
	return &regressionTestFixture{
		TB: t,
	}
}

func (f *regressionTestFixture) Server() ServerFixture {
	return newServerFixture(f)
}

func (f *regressionTestFixture) Middleware() MiddlewareFixture {
	return newMiddlewareFixture(f)
}
