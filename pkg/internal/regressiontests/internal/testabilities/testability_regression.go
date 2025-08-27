package testabilities

import "testing"

func New(t testing.TB, opts ...func(*creationOptions)) (given RegressionTestFixture, then RegressionTestAssertion) {
	return Given(t, opts...), Then(t)
}
