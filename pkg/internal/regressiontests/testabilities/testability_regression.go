package testabilities

import "testing"

func New(t testing.TB) (given RegressionTestFixture, then RegressionTestAssertion) {
	return Given(t), Then(t)
}
