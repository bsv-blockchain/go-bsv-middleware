package testabilities

import (
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/stretchr/testify/assert"
)

type AuthFetchResponseAssertion interface {
	HasStatus(int) AuthFetchResponseAssertion
	HasHeader(string) AuthFetchResponseAssertion
	HasBody(any) AuthFetchResponseAssertion
}

type authFetchResponseAssertion struct {
	testing.TB
	response *typescript.AuthFetchResponse
}

func (a *authFetchResponseAssertion) HasStatus(status int) AuthFetchResponseAssertion {
	a.Helper()
	assert.Equal(a, status, a.response.Status, "fetch should return status 200")
	return a
}

func (a *authFetchResponseAssertion) HasHeader(headerName string) AuthFetchResponseAssertion {
	a.Helper()
	assert.Contains(a, a.response.Headers, headerName)
	return a
}

func (a *authFetchResponseAssertion) HasBody(body any) AuthFetchResponseAssertion {
	a.Helper()
	assert.Equal(a, a.response.Body, body)
	return a
}
