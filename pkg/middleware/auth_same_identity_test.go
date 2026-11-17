package middleware_test

import (
	"net/http"
	"sync"
	"testing"
	"time"

	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
)

// Two clients holding the SAME identity key (one wallet run from two
// processes, e.g. a service on two hosts) each keep their own session with the
// server. Every response must be signed on the session its request came in
// on; signing it on the identity's most recently used session instead hands
// the other client's session nonce to this one, which rejects the reply with
// session-not-found even though the server handled the request.
func TestConcurrentClientsSharingAnIdentityKey(t *testing.T) {
	given := testabilities.Given(t)
	authMiddleware := given.Middleware().NewAuth()
	cleanup := given.Server().WithMiddleware(authMiddleware).
		WithRoute("/", func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Millisecond) // the window in which the other client's session gets used
			w.WriteHeader(http.StatusNoContent)
		}).
		Started()
	defer cleanup()

	alice := testusers.NewAlice(t)
	url := given.Server().URL().String()

	const clientsN, requestsEach = 2, 20
	var wg sync.WaitGroup
	errs := make(chan error, clientsN*requestsEach)
	for c := 0; c < clientsN; c++ {
		httpClient, done := given.Client().ForUser(alice)
		defer done()
		// one handshake each, before the concurrent part
		resp, err := httpClient.Fetch(t.Context(), url, &clients.SimplifiedFetchRequestOptions{})
		require.NoError(t, err)
		_ = resp.Body.Close()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < requestsEach; i++ {
				resp, err := httpClient.Fetch(t.Context(), url, &clients.SimplifiedFetchRequestOptions{})
				if err != nil {
					errs <- err
					continue
				}
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	close(errs)
	var failed []string
	for err := range errs {
		failed = append(failed, err.Error())
	}
	require.Empty(t, failed, "%d of %d requests failed", len(failed), clientsN*requestsEach)
}
