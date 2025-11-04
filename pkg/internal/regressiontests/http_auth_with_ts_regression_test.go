//goland:noinspection DuplicatedCode // intentionally those tests look very similar to regression tests.
package regressiontests

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/testabilities"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testmode"
	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

func TestAuthMiddlewareAuthenticatesTypescriptClient(t *testing.T) {
	t.Parallel()

	// Skip if Docker is not available
	if !isDockerAvailable(t) {
		t.Skip("Skipping test: Docker is not available. Start Docker or set TEST_GRPC_MODE=local with a running gRPC server.")
	}

	givenBeforeAll := testabilities.Given(t)

	grpcCleanup := givenBeforeAll.TypescriptGrpcServerStarted()
	defer grpcCleanup()

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
		// FIXME(Issue: #145): uncomment and implement this test when empty response body will be fixed.
		// "server responding with no content": {
		// 	serverRespondingWithNoContent: true,
		// },
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			// given:
			given, then := testabilities.New(t, testabilities.WithBeforeAll(givenBeforeAll))

			// and:
			alice := testusers.NewAlice(t)

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
						HasBody(test.body).
						HasIdentityOfUser(alice)

					_, err := w.Write([]byte("Pong!"))
					assert.NoError(t, err)
				}).
				Started()
			defer cleanup()

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
			defer func() { _ = response.Body.Close() }()

			// and:
			then.Response(response).
				HasStatus(http.StatusOK).
				HasHeader("x-bsv-auth-identity-key").
				HasBody("Pong!")
		})
	}
}

func TestAuthMiddlewareAuthenticatesSubsequentTypescriptClientCalls(t *testing.T) {
	t.Parallel()

	// Skip if Docker is not available
	if !isDockerAvailable(t) {
		t.Skip("Skipping test: Docker is not available. Start Docker or set TEST_GRPC_MODE=local with a running gRPC server.")
	}

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
				// FIXME(Issue: #145): unify with integration tests when empty response body will be fixed
				_, err := w.Write([]byte("Pong!"))
				assert.NoError(t, err)
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
		defer func() { _ = response.Body.Close() }()
		require.NotNil(t, response, "first response should not be nil")
		require.Equal(t, http.StatusOK, response.StatusCode, "first response status code should be 200")

		// when:
		response, err = httpClient.Fetch(t.Context(), given.Server().URL().String(), &clients.SimplifiedFetchRequestOptions{})

		// then:
		require.NoError(t, err, "second request should succeed")
		defer func() { _ = response.Body.Close() }()
		require.NotNil(t, response, "second response should not be nil")
		require.Equal(t, http.StatusOK, response.StatusCode, "second response status code should be 200")
	})

	t.Run("make multiple requests with different clients for the same user", func(t *testing.T) {
		// given:
		given := testabilities.Given(t, testabilities.WithBeforeAll(givenBeforeAll))

		// and:
		authMiddleware := given.Middleware().NewAuth()

		// and:
		cleanup := given.Server().WithMiddleware(authMiddleware).
			WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
				// FIXME(Issue: #145): unify with integration tests when empty response body will be fixed
				_, err := w.Write([]byte("Pong!"))
				assert.NoError(t, err)
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
		defer func() { _ = response.Body.Close() }()
		require.NotNil(t, response, "first response should not be nil")
		require.Equal(t, http.StatusOK, response.StatusCode, "first response status code should be 200")

		// when:
		newHttpClient, newClientCleanup := given.Client().ForUser(alice)
		defer newClientCleanup()

		// and:
		response, err = newHttpClient.Fetch(t.Context(), given.Server().URL().String(), &clients.SimplifiedFetchRequestOptions{})

		// then:
		require.NoError(t, err, "second request should succeed")
		defer func() { _ = response.Body.Close() }()
		require.NotNil(t, response, "second response should not be nil")
		require.Equal(t, http.StatusOK, response.StatusCode, "second response status code should be 200")
	})
}

// isDockerAvailable checks if Docker is available and running.
// It respects the TEST_GRPC_MODE environment variable:
// - If set to "local", returns false (skip Docker tests)
// - If set to "docker" or not set, checks if Docker is actually available
func isDockerAvailable(t *testing.T) bool {
	// Check if user explicitly set local mode
	if os.Getenv("TEST_GRPC_MODE") == testmode.GrpcLocalMode {
		return false
	}

	// Use defer/recover to catch panics from testcontainers when Docker is not available
	available := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Docker check panicked (Docker likely not available): %v", r)
				available = false
			}
		}()

		// Try to ping Docker daemon with a timeout
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		provider, err := testcontainers.NewDockerProvider()
		if err != nil {
			t.Logf("Docker provider initialization failed: %v", err)
			available = false
			return
		}
		defer func() {
			_ = provider.Close()
		}()

		// Try to get Docker info to verify connectivity
		if err := provider.Health(ctx); err != nil {
			t.Logf("Docker health check failed: %v", err)
			available = false
			return
		}

		available = true
	}()

	return available
}
