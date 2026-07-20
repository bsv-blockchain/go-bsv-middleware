package testabilities

import (
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/require"
)

// portScanAttempts is the number of times we scan the whole port list looking
// for a free port before giving up. A single scan almost always succeeds; the
// extra attempts only cover the rare case where every candidate port is
// momentarily busy under heavy parallel load.
const portScanAttempts = 3

// portScanBackoff is how long we wait between full scans of the port list.
const portScanBackoff = 50 * time.Millisecond

type MiddlewareHTTPHandlerFactory interface {
	HTTPHandler(next http.Handler) http.Handler
}

type ServerFixture interface {
	WithRoute(pattern string, handler func(w http.ResponseWriter, r *http.Request)) ServerBuilder
	WithMiddleware(middleware MiddlewareHTTPHandlerFactory) ServerBuilder
	WithMiddlewareFunc(middlewareFunc func(next http.Handler) http.Handler) ServerBuilder

	URL() *url.URL
}

type ServerBuilder interface {
	WithRoute(pattern string, handler func(w http.ResponseWriter, r *http.Request)) ServerBuilder
	WithMiddleware(middleware MiddlewareHTTPHandlerFactory) ServerBuilder
	WithMiddlewareFunc(middlewareFunc func(next http.Handler) http.Handler) ServerBuilder
	Started() (cleanup func())
}

type ServerFixtureOptions struct {
	serverPorts []int
}

type serverFixture struct {
	testing.TB

	mux        *http.ServeMux
	middleware []middlewareFunc
	server     *httptest.Server
	ports      []int
}

type middlewareFunc func(next http.Handler) http.Handler

func NewServerFixture(t testing.TB, opts ...func(*ServerFixtureOptions)) ServerFixture {
	options := to.OptionsWithDefault(ServerFixtureOptions{}, opts...)

	return &serverFixture{
		TB:         t,
		mux:        http.NewServeMux(),
		middleware: make([]middlewareFunc, 0),
		ports:      options.serverPorts,
	}
}

func (f *serverFixture) WithRoute(pattern string, handler func(w http.ResponseWriter, r *http.Request)) ServerBuilder {
	f.mux.HandleFunc(pattern, handler)
	return f
}

// WithMiddleware adds a middleware handler to the server fixture, wrapping the HTTP handler chain in the specified middleware.
// Middleware will be applied in opposite order - so the call chain will go from the first to the last.
func (f *serverFixture) WithMiddleware(handler MiddlewareHTTPHandlerFactory) ServerBuilder {
	return f.WithMiddlewareFunc(handler.HTTPHandler)
}

// WithMiddlewareFunc adds a middleware function to the server fixture, wrapping the HTTP handler chain in the specified middleware.
// Middleware will be applied in opposite order - so the call chain will go from the first to the last.
func (f *serverFixture) WithMiddlewareFunc(middleware func(next http.Handler) http.Handler) ServerBuilder {
	f.middleware = append(f.middleware, middleware)
	return f
}

func (f *serverFixture) Started() (cleanup func()) {
	server, cleanup := f.newServer()
	f.server = server

	return cleanup
}

func (f *serverFixture) URL() *url.URL {
	require.NotNil(f, f.server, "server must be started before URL can be retrieved: invalid test setup")

	serverURL, err := url.Parse(f.server.URL)
	require.NoErrorf(f, err, "failed to parse server URL (%s): invalid test setup", f.server.URL)

	return serverURL
}

func (f *serverFixture) handler() http.Handler {
	var handler http.Handler = f.mux

	for i := len(f.middleware) - 1; i >= 0; i-- {
		handler = f.middleware[i](handler)
	}

	return handler
}

func (f *serverFixture) newServer() (server *httptest.Server, cleanup func()) {
	if len(f.ports) == 0 {
		server = httptest.NewServer(f.handler())
	} else {
		listener := f.listenOnFreePort()

		server = &httptest.Server{
			Listener: listener,
			Config: &http.Server{
				Handler:           f.handler(),
				ReadHeaderTimeout: 10 * time.Second,
			},
		}
		server.Start()
	}

	cleanup = func() {
		server.Close()
	}
	return server, cleanup
}

// listenOnFreePort binds to the first free port from the configured list and
// returns the listener. To avoid many parallel tests contending on the same
// low ports (which wastes bind syscalls and makes port acquisition flaky under
// load), the scan starts at a random offset and wraps around the whole list.
// The full list is scanned up to portScanAttempts times with a short backoff
// so a transient burst of busy ports does not fail the test outright.
func (f *serverFixture) listenOnFreePort() net.Listener {
	f.Helper()
	f.Log("trying to find free port from ports list to start the server")

	lc := &net.ListenConfig{}
	ports := len(f.ports)

	for attempt := range portScanAttempts {
		if err := f.Context().Err(); err != nil {
			break
		}

		// Non-cryptographic use: the random start only spreads concurrent tests
		// across the port list to reduce bind contention.
		start := rand.IntN(ports) //nolint:gosec // test-only port spreading, not security sensitive
		for i := range ports {
			port := f.ports[(start+i)%ports]
			listener, err := lc.Listen(f.Context(), "tcp", "127.0.0.1:"+to.StringFromInteger(port))
			if err == nil && listener != nil {
				f.Log("starting server on port:", port)
				return listener
			}
		}

		if attempt < portScanAttempts-1 {
			f.Log("no free port found in ports list, retrying after backoff")
			time.Sleep(portScanBackoff)
		}
	}

	require.FailNowf(f, "failed to find free port",
		"no free port available in ports list %v after %d attempts", f.ports, portScanAttempts)
	return nil
}
