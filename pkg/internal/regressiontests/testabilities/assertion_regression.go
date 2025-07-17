package testabilities

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
)

type RegressionTestAssertion interface {
	Request(*http.Request) RequestAssertion
	Response(*typescript.AuthFetchResponse) AuthFetchResponseAssertion
}

type regressionTestAssertion struct {
	testing.TB
}

func Then(t testing.TB) RegressionTestAssertion {
	return &regressionTestAssertion{TB: t}
}

func (a *regressionTestAssertion) Request(request *http.Request) RequestAssertion {
	return &requestAssertion{
		TB:      a,
		request: request,
	}
}

func (a *regressionTestAssertion) Response(response *typescript.AuthFetchResponse) AuthFetchResponseAssertion {
	return &authFetchResponseAssertion{
		TB:       a,
		response: response,
	}
}
