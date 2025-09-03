//goland:noinspection DuplicatedCode // intentionally those tests looks the very similar to regression tests.
package middleware_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddlewareAndAuthFetchIntegration(t *testing.T) {
	testCases := map[string]struct {
		path    string
		method  string
		headers map[string]string
		query   string
		body    string
	}{
		"get request on server root": {
			method: http.MethodGet,
		},
		"get request on path": {
			method: http.MethodGet,
			path:   "/ping",
		},
		"get with query params": {
			method: http.MethodGet,
			query:  "test=123&other=abc",
		},
		"get request on path with query params": {
			method: http.MethodGet,
			path:   "/ping",
			query:  "test=123&other=abc",
		},
		"get with authorization headers": {
			method: http.MethodGet,
			headers: map[string]string{
				"Authorization": "123",
			},
		},
		"get with custom x-bsv headers": {
			method: http.MethodGet,
			headers: map[string]string{
				"X-Bsv-Test": "true",
			},
		},
		"get with path and headers": {
			method: http.MethodGet,
			path:   "/ping",
			headers: map[string]string{
				"Authorization": "123",
			},
		},
		"post request without body": {
			method: http.MethodPost,
		},
		"post request on path without body": {
			method: http.MethodPost,
			path:   "/ping",
		},
		"post request with content-type but no body": {
			method: http.MethodPost,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
		"post request on path with json empty body": {
			method: http.MethodPost,
			path:   "/ping",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
		"post request with body": {
			method: http.MethodPost,
			body:   "Ping",
		},
		"post request on path with body": {
			method: http.MethodPost,
			path:   "/ping",
			body:   "Ping",
		},
		"post request with body and content-type": {
			method: http.MethodPost,
			body:   `{ "ping" : true }`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
		"post request with body and content-type and authorization header": {
			method: http.MethodPost,
			body:   `{ "ping" : true }`,
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "123",
			},
		},
		"post request with body and content-type and authorization and bsv header": {
			method: http.MethodPost,
			body:   `{ "ping" : true }`,
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "123",
				"X-Bsv-Test":    "true",
			},
		},
		"post request with query params and body and headers": {
			method: http.MethodPost,
			query:  "test=123&other=abc",
			body:   `{ "ping" : true }`,
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "123",
				"X-Bsv-Test":    "true",
			},
		},
		"post request on path with query params and body and headers": {
			method: http.MethodPost,
			path:   "/ping",
			query:  "test=123&other=abc",
			body:   `{ "ping" : true }`,
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "123",
				"X-Bsv-Test":    "true",
			},
		},
		"options request": {
			method: http.MethodOptions,
		},
		"options request on path": {
			method: http.MethodOptions,
			path:   "/ping",
		},
		"options request with query params": {
			method: http.MethodOptions,
			query:  "test=123&other=abc",
		},
		"options request on path with query params": {
			method: http.MethodOptions,
			path:   "/ping",
			query:  "test=123&other=abc",
		},
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			// given:
			given, then := testabilities.New(t)

			// and:
			authMiddleware := given.Middleware().NewAuth()

			// and:
			cleanup := given.Server().WithMiddleware(authMiddleware).
				WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
					then.Request(r).
						HasMethod(test.method).
						HasPath(test.path).
						HasQueryMatching(url.PathEscape(test.query)).
						HasHeadersContaining(test.headers).
						HasBody(test.body)

					// TODO check identity key

					_, err := w.Write([]byte("Pong!"))
					require.NoError(t, err)
				}).
				Started()
			defer cleanup()

			// and:
			alice := testusers.NewAlice(t)

			// and:
			httpClient, cleanup := given.Client().ForUser(alice)
			defer cleanup()

			// when:
			serverURL := given.Server().URL()
			serverURL.Path = test.path
			serverURL.RawQuery = test.query

			response, err := httpClient.Fetch(t.Context(), serverURL.String(), &clients.SimplifiedFetchRequestOptions{
				Method:       test.method,
				Headers:      test.headers,
				Body:         []byte(test.body),
				RetryCounter: to.Ptr(1),
			})

			// then:
			require.NoError(t, err, "fetch should succeed")

			// and:
			then.Response(response).
				HasStatus(200).
				HasHeader("x-bsv-auth-identity-key").
				HasBody("Pong!")
		})
	}
}

func TestAuthMiddlewareHandleSubsequentRequests(t *testing.T) {
	t.Run("multiple requests with the same client", func(t *testing.T) {
		// given:
		given := testabilities.Given(t)

		// and:
		authMiddleware := given.Middleware().NewAuth()

		// and:
		cleanup := given.Server().WithMiddleware(authMiddleware).
			WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte("Pong!"))
				require.NoError(t, err)
			}).
			Started()
		defer cleanup()

		// and:
		alice := testusers.NewAlice(t)

		// and:
		httpClient, cleanup := given.Client().ForUser(alice)
		defer cleanup()

		// when:
		response, err := httpClient.Fetch(t.Context(), given.Server().URL().String(), &clients.SimplifiedFetchRequestOptions{})

		// then:
		require.NoError(t, err, "first request should succeed")
		require.NotNil(t, response, "first response should not be nil")
		require.Equal(t, 200, response.StatusCode, "first response status code should be 200")

		// when:
		response, err = httpClient.Fetch(t.Context(), given.Server().URL().String(), &clients.SimplifiedFetchRequestOptions{})

		// then:
		require.NoError(t, err, "second request should succeed")
		require.NotNil(t, response, "second response should not be nil")
		require.Equal(t, 200, response.StatusCode, "second response status code should be 200")
	})

	t.Run("multiple requests with different clients for the same user", func(t *testing.T) {
		// given:
		given := testabilities.Given(t)

		// and:
		authMiddleware := given.Middleware().NewAuth()

		// and:
		cleanup := given.Server().WithMiddleware(authMiddleware).
			WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte("Pong!"))
				require.NoError(t, err)
			}).
			Started()
		defer cleanup()

		// and:
		alice := testusers.NewAlice(t)

		// and:
		httpClient, cleanup := given.Client().ForUser(alice)
		defer cleanup()

		// when:
		response, err := httpClient.Fetch(t.Context(), given.Server().URL().String(), &clients.SimplifiedFetchRequestOptions{})

		// then:
		require.NoError(t, err, "first request should succeed")
		require.NotNil(t, response, "first response should not be nil")
		require.Equal(t, 200, response.StatusCode, "first response status code should be 200")

		// when:
		newHttpClient, newClientCleanup := given.Client().ForUser(alice)
		defer newClientCleanup()

		// and:
		response, err = newHttpClient.Fetch(t.Context(), given.Server().URL().String(), &clients.SimplifiedFetchRequestOptions{})

		// then:
		require.NoError(t, err, "second request should succeed")
		require.NotNil(t, response, "second response should not be nil")
		require.Equal(t, 200, response.StatusCode, "second response status code should be 200")
	})

}
