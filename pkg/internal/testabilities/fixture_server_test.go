package testabilities

import (
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/go-softwarelab/common/pkg/seq"
	"github.com/stretchr/testify/require"
)

// TestServerFixtureListensOnPortFromList verifies that when a port list is
// configured, the server binds to one of those ports and actually serves.
func TestServerFixtureListensOnPortFromList(t *testing.T) {
	ports := seq.Collect(seq.Range(56000, 56020))

	fixture := NewServerFixture(t, func(o *ServerFixtureOptions) {
		o.serverPorts = ports
	})

	cleanup := fixture.
		WithRoute("/", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}).
		Started()
	defer cleanup()

	serverURL := fixture.URL()
	require.Contains(t, ports, mustPort(t, serverURL.Port()),
		"server must listen on a port from the configured list")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL.String(), nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", string(body))
}

// TestServerFixtureAvoidsPortContention starts several servers that all share
// the same port list at the same time and asserts they each get a distinct
// port. This guards the parallel regression-test setup, where many servers are
// alive concurrently and must not collide.
func TestServerFixtureAvoidsPortContention(t *testing.T) {
	const servers = 10
	// A list barely larger than the number of servers forces the scan to skip
	// over already-bound ports rather than getting lucky with spare capacity.
	ports := seq.Collect(seq.Range(56100, 56100+servers+5))

	usedPorts := make(map[int]struct{}, servers)
	for range servers {
		fixture := NewServerFixture(t, func(o *ServerFixtureOptions) {
			o.serverPorts = ports
		})

		cleanup := fixture.
			WithRoute("/", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}).
			Started()
		defer cleanup()

		port := mustPort(t, fixture.URL().Port())
		require.Contains(t, ports, port, "server must listen on a port from the configured list")

		_, reused := usedPorts[port]
		require.Falsef(t, reused, "port %d was handed out to two concurrent servers", port)
		usedPorts[port] = struct{}{}
	}

	require.Len(t, usedPorts, servers, "each concurrent server must get a unique port")
}

func mustPort(t *testing.T, port string) int {
	t.Helper()
	value, err := strconv.Atoi(port)
	require.NoErrorf(t, err, "failed to parse port %q", port)
	return value
}
