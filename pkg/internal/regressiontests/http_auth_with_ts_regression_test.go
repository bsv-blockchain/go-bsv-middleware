package regressiontests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddlewareAuthenticatesTypescriptClient(t *testing.T) {
	testCases := map[string]struct {
		method  string
		query   string
		body    any
		headers map[string]string
	}{
		"get request": {
			method:  "GET",
			query:   "",
			body:    nil,
			headers: nil,
		},
		"get request with query params": {
			method:  "GET",
			query:   "test=123&other=abc",
			body:    nil,
			headers: nil,
		},
		"get request with headers": {
			method: "GET",
			query:  "",
			body:   nil,
			headers: map[string]string{
				// WARNING: Only content-type, authorization, and x-bsv-* headers are supported by auth fetch
				"Authorization": "123",
				"Content-Type":  "text/plain",
			},
		},
		"post request": {
			method: "POST",
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
			key, err := primitives.NewPrivateKey()
			require.NoError(t, err)
			wallet, err := utils.NewCompletedProtoWallet(key)
			require.NoError(t, err)

			// and:
			authMiddleware, err := auth.New(auth.Config{
				AllowUnauthenticated: false,
				Wallet:               wallet,
				Logger:               logging.NewTestLogger(t),
			})
			require.NoError(t, err)

			mux := http.NewServeMux()

			mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != test.method {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}

				bytes, err2 := io.ReadAll(r.Body)
				assert.NoError(t, err2, "failed to read request body: invalid test setup")

				if test.body == nil {
					assert.Empty(t, bytes, "request body should be empty")
				} else {
					var body map[string]string
					err2 = json.Unmarshal(bytes, &body)
					assert.NoError(t, err2, "failed to unmarshal request body")
					assert.Equal(t, test.body, body, "request body should match")
				}

				assert.Equal(t, test.query, r.URL.RawQuery, "query params received by handler should match")

				for headerName, headerValue := range test.headers {
					assert.Equalf(t, headerValue, r.Header.Get(headerName), "header %s received by handler should match", headerName)
				}

				// TODO check indentity key
				_, err2 = w.Write([]byte("Pong!"))
				require.NoError(t, err)
			})

			server := httptest.NewServer(authMiddleware.Handler(mux))
			defer server.Close()

			// when:
			requestURL, err := url.Parse(server.URL)
			require.NoError(t, err, "invalid server url: invalid test setup")
			requestURL.Path = "/ping"
			requestURL.RawQuery = test.query

			response, err := typescript.AuthFetch(t,
				requestURL.String(),
				typescript.WithMethod(test.method),
				typescript.WithHeaders(test.headers),
				typescript.WithBody(test.body),
			)

			// then:
			assert.NoError(t, err, "fetch should connect without error")

			// and:
			require.NotNil(t, response)
			assert.Equal(t, 200, response.Status, "fetch should return status 200")
			assert.Contains(t, response.Headers, "x-bsv-auth-identity-key")
			assert.NotEmpty(t, response.Body, "Pong!")

		})
	}
}
