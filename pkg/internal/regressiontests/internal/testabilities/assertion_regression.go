package testabilities

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities"
)

type RequestAssertion = testabilities.RequestAssertion
type ResponseAssertion = testabilities.ResponseAssertion

type RegressionTestAssertion interface {
	Request(*http.Request) RequestAssertion
	Response(*http.Response) ResponseAssertion
}

func Then(t testing.TB) RegressionTestAssertion {
	return testabilities.Then(t)
}
