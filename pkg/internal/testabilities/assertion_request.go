package testabilities

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type RequestAssertion interface {
	HasMethod(method string) RequestAssertion
	HasHeadersContaining(headers map[string]string) RequestAssertion
	HasQueryMatching(query string) RequestAssertion
	HasBodyMatching(expectedBody map[string]string) RequestAssertion
	HasBody(expectedBody string) RequestAssertion
	HasPath(path string) RequestAssertion
	HasIdentityOfUser(user *testusers.UserWithWallet) RequestAssertion
}

type requestAssertion struct {
	testing.TB

	request *http.Request
}

func NewRequestAssertion(t testing.TB, request *http.Request) RequestAssertion {
	return &requestAssertion{
		TB:      t,
		request: request,
	}
}

func (a *requestAssertion) HasMethod(httpMethod string) RequestAssertion {
	a.Helper()
	if httpMethod == "" {
		httpMethod = http.MethodGet
	}
	assert.Equalf(a, httpMethod, a.request.Method, "Expect to receive %s request", httpMethod)
	return a
}

func (a *requestAssertion) HasPath(path string) RequestAssertion {
	a.Helper()
	if path == "" {
		// server will add "/" to path automatically so the assertion must adjust to this behavior.
		path = "/"
	}
	assert.Equal(a, path, a.request.URL.Path, "request path received by handler should match")
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
	bodyBytes := a.extractRequestBody()

	if expectedBody == nil {
		assert.Empty(a, bodyBytes, "request body should be empty")
	} else {
		var body map[string]string
		err := json.Unmarshal(bodyBytes, &body)
		if assert.NoError(a, err, "failed to unmarshal request body") {
			assert.Equal(a, expectedBody, body, "request body should match")
		}
	}

	return a
}

func (a *requestAssertion) HasBody(expectedBody string) RequestAssertion {
	a.Helper()
	bodyBytes := a.extractRequestBody()

	if expectedBody == "" {
		assert.Empty(a, bodyBytes, "request body should be empty")
	} else {
		assert.Equal(a, expectedBody, string(bodyBytes), "request body should match")
	}
	return a
}

func (a *requestAssertion) HasIdentityOfUser(user *testusers.UserWithWallet) RequestAssertion {
	a.Helper()

	identity, err := middleware.ShouldGetAuthenticatedIdentity(a.request.Context())
	if assert.NoError(a, err, "cannot get authenticated identity from context") {
		assert.Equalf(a, user.PublicKey(a).ToDERHex(), identity.ToDERHex(), "identity from request should match %s identity", user.Name)
	}
	return a
}

func (a *requestAssertion) extractRequestBody() []byte {
	a.Helper()
	bodyBytes, err := io.ReadAll(a.request.Body)
	require.NoError(a, err, "failed to read request body: invalid test setup")
	// ensure the body is not closed.
	a.request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes
}
