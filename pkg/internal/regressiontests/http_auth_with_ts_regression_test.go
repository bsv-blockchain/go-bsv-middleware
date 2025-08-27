package regressiontests

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/testabilities"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddlewareAuthenticatesTypescriptClient(t *testing.T) {
	t.Parallel()
	givenBeforeAll := testabilities.Given(t)

	_ = givenBeforeAll.TypescriptGrpcServerStarted()
	// defer grpcCleanup()

	testCases := map[string]struct {
		path    string
		method  string
		query   string
		body    string
		headers map[string]string
	}{
		"default request": {},
		"get request": {
			method: http.MethodGet,
		},
		"get request on path": {
			method: http.MethodGet,
			path:   "/ping",
		},
		"get request with query params": {
			method: http.MethodGet,
			path:   "/ping",
			query:  "test=123&other=abc",
		},
		"get request with headers": {
			method: http.MethodGet,
			path:   "/ping",
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
			body:   `{ "ping" : true }`,
			headers: map[string]string{
				// WARNING: Content-Type is required for request with body by auth fetch
				"Content-Type": "application/json",
			},
		},
		"options request": {
			method: http.MethodOptions,
		},
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			// given:
			given, then := testabilities.New(t, testabilities.WithBeforeAll(givenBeforeAll))

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

func TestAuthMiddlewareAuthenticatesSubsequentTypescriptClientCalls(t *testing.T) {
	t.Parallel()

	givenBeforeAll := testabilities.Given(t)

	grpcCleanup := givenBeforeAll.TypescriptGrpcServerStarted()
	defer grpcCleanup()

	t.Run("make multiple requests with the same client", func(t *testing.T) {
		// given:
		given := testabilities.Given(t, testabilities.WithBeforeAll(givenBeforeAll))

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

	t.Run("make multiple requests with different clients for the same user", func(t *testing.T) {
		// given:
		given := testabilities.Given(t, testabilities.WithBeforeAll(givenBeforeAll))

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
