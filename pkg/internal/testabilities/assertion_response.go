package testabilities

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ResponseAssertion interface {
	HasStatus(int) ResponseAssertion
	HasHeader(string) ResponseAssertion
	HasBody(string) ResponseAssertion
}

type httpResponseAssertion struct {
	testing.TB
	response *http.Response
}

func NewResponseAssertion(t testing.TB, response *http.Response) ResponseAssertion {
	return &httpResponseAssertion{
		TB:       t,
		response: response,
	}
}

func (a *httpResponseAssertion) HasStatus(status int) ResponseAssertion {
	a.Helper()
	assert.Equalf(a, status, a.response.StatusCode, "fetch should return status %d", status)
	return a
}

func (a *httpResponseAssertion) HasHeader(headerName string) ResponseAssertion {
	a.Helper()
	assert.NotEmptyf(a, a.response.Header.Get(headerName), "response should have header %s", headerName)
	return a
}

func (a *httpResponseAssertion) HasBody(body string) ResponseAssertion {
	a.Helper()
	responseBody, err := io.ReadAll(a.response.Body)
	if assert.NoError(a, err, "body should be readable") {
		assert.Equal(a, body, string(responseBody))
	}
	return a
}
