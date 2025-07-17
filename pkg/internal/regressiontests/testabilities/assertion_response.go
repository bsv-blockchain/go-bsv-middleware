package testabilities

import (
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type AuthFetchResponseAssertion interface {
	WithNoError(error) SuccessAuthFetchResponseAssertion
}

type SuccessAuthFetchResponseAssertion interface {
	HasStatus(int) SuccessAuthFetchResponseAssertion
	HasHeader(string) SuccessAuthFetchResponseAssertion
	HasBody(any) SuccessAuthFetchResponseAssertion
}

type authFetchResponseAssertion struct {
	testing.TB
	response *typescript.AuthFetchResponse
}

func (a *authFetchResponseAssertion) WithNoError(err error) SuccessAuthFetchResponseAssertion {
	assert.NoError(a, err, "fetch should result with no error")
	require.NotNil(a, a.response, "fetch should return a response")
	return a
}

func (a *authFetchResponseAssertion) HasStatus(status int) SuccessAuthFetchResponseAssertion {
	assert.Equal(a, status, a.response.Status, "fetch should return status 200")
	return a
}

func (a *authFetchResponseAssertion) HasHeader(headerName string) SuccessAuthFetchResponseAssertion {
	assert.Contains(a, a.response.Headers, "x-bsv-auth-identity-key")
	return a
}

func (a *authFetchResponseAssertion) HasBody(body any) SuccessAuthFetchResponseAssertion {
	assert.Equal(a, a.response.Body, body)
	return a
}
