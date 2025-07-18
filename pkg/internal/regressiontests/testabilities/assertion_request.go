package testabilities

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type RequestAssertion interface {
	HasMethod(string) RequestAssertion
	HasHeadersContaining(map[string]string) RequestAssertion
	HasQueryMatching(string) RequestAssertion
	HasBodyMatching(map[string]string) RequestAssertion
	// TODO
	// IsAuthenticatedFor(identityKey ???) RequestAssertion
}

type requestAssertion struct {
	testing.TB
	request *http.Request
}

func (a *requestAssertion) HasMethod(httpMethod string) RequestAssertion {
	a.Helper()
	assert.Equalf(a, httpMethod, a.request.Method, "Expect to receive %s request", httpMethod)
	return a
}

func (a *requestAssertion) HasHeadersContaining(headers map[string]string) RequestAssertion {
	a.Helper()
	for headerName, headerValue := range headers {
		assert.Equalf(a, headerValue, a.request.Header.Get(headerName), "Header %s value received by handler should match", headerName)
	}

	return a
}

func (a *requestAssertion) HasQueryMatching(query string) RequestAssertion {
	a.Helper()
	assert.Equal(a, query, a.request.URL.RawQuery, "query params received by handler should match")
	return a
}

func (a *requestAssertion) HasBodyMatching(expectedBody map[string]string) RequestAssertion {
	a.Helper()
	bodyBytes, err := io.ReadAll(a.request.Body)
	assert.NoError(a, err, "failed to read request body: invalid test setup")
	// ensure the body is not closed.
	a.request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	if expectedBody == nil {
		assert.Empty(a, bodyBytes, "request body should be empty")
	} else {
		var body map[string]string
		err = json.Unmarshal(bodyBytes, &body)
		if assert.NoError(a, err, "failed to unmarshal request body") {
			assert.Equal(a, expectedBody, body, "request body should match")
		}
	}

	return a
}
