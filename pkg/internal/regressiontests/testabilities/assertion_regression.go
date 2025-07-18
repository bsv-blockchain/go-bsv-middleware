package testabilities

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/stretchr/testify/require"
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
	a.Helper()
	require.NotNil(a, response, "response should not be nil")

	return &authFetchResponseAssertion{
		TB:       a,
		response: response,
	}
}
