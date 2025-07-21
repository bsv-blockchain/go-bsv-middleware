//go:build regressiontest

package regressiontests

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/testabilities"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddlewareAuthenticatesTypescriptClient(t *testing.T) {
	testCases := map[string]struct {
		path    string
		method  string
		query   string
		body    map[string]string
		headers map[string]string
	}{
		"get request": {
			method:  http.MethodGet,
			query:   "",
			body:    nil,
			headers: nil,
		},
		"get request on path": {
			method: http.MethodGet,
			path:   "/ping",
			query:  "",
			body:   nil,
		},
		"get request with query params": {
			method:  http.MethodGet,
			path:    "/ping",
			query:   "test=123&other=abc",
			body:    nil,
			headers: nil,
		},
		"get request with headers": {
			method: http.MethodGet,
			path:   "/ping",
			query:  "",
			body:   nil,
			headers: map[string]string{
				// WARNING: Only content-type, authorization, and x-bsv-* headers are supported by auth fetch
				"Authorization": "123",
				"Content-Type":  "text/plain",
				"X-Bsv-Test":    "true",
			},
		},
		"post request": {
			method: http.MethodPost,
			path:   "/ping",
			query:  "",
			body: map[string]string{
				"test":  "123",
				"other": "abc",
			},
			headers: map[string]string{
				// WARNING: Content-Type is required for request with body by auth fetch
				"Content-Type": "application/json",
			},
		},
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			// given:
			given, then := testabilities.New(t)

			// and:
			authMiddleware := given.Middleware().NewAuth()

			// and:
			cleanup := given.Server().
				WithMiddlewareFunc(authMiddleware.Handler).
				WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
					then.Request(r).
						HasMethod(test.method).
						HasPath(test.path).
						HasQueryMatching(url.PathEscape(test.query)).
						HasHeadersContaining(test.headers).
						HasBodyMatching(test.body)

					// TODO check identity key

					_, err := w.Write([]byte("Pong!"))
					require.NoError(t, err)
				}).
				Started()
			defer cleanup()

			// when:
			serverURL := given.Server().URL()
			serverURL.Path = test.path
			serverURL.RawQuery = test.query

			response := typescript.AuthFetch(t,
				serverURL.String(),
				typescript.WithMethod(test.method),
				typescript.WithHeaders(test.headers),
				typescript.WithBody(test.body),
			)

			// then:
			then.Response(response).
				HasStatus(200).
				HasHeader("x-bsv-auth-identity-key").
				HasBody("Pong!")
		})
	}
}
