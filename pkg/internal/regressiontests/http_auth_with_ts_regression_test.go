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
		"get request with query params": {
			method:  http.MethodGet,
			query:   "test=123&other=abc",
			body:    nil,
			headers: nil,
		},
		"get request with headers": {
			method: http.MethodGet,
			query:  "",
			body:   nil,
			headers: map[string]string{
				// WARNING: Only content-type, authorization, and x-bsv-* headers are supported by auth fetch
				"Authorization": "123",
				"Content-Type":  "text/plain",
			},
		},
		"post request": {
			method: http.MethodPost,
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
		"invalid query params": {
			method: http.MethodPost,
			query:  "shirts size",
		},
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			// given:
			given, then := testabilities.New(t)

			// and:
			authMiddleware := given.Middleware().NewAuth()

			// and:
			url, cleanup := given.Server().
				WithMiddleware(authMiddleware.Handler).
				WithRoute("/ping", func(w http.ResponseWriter, r *http.Request) {
					then.Request(r).
						HasMethod(test.method).
						HasHeadersContaining(test.headers).
						HasQueryMatching(url.PathEscape(test.query)).
						HasBodyMatching(test.body)

					// TODO check identity key

					_, err := w.Write([]byte("Pong!"))
					require.NoError(t, err)
				}).
				Started()
			defer cleanup()

			// when:
			url.Path = "/ping"
			url.RawQuery = test.query

			response := typescript.AuthFetch(t,
				url.String(),
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
