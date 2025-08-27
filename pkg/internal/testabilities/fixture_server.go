package testabilities

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/require"
)

type MiddlewareHandler interface {
	Handler(next http.Handler) http.Handler
}

type ServerFixture interface {
	WithRoute(pattern string, handler func(w http.ResponseWriter, r *http.Request)) ServerBuilder
	WithMiddleware(MiddlewareHandler) ServerBuilder
	WithMiddlewareFunc(func(next http.Handler) http.Handler) ServerBuilder

	URL() *url.URL
}

type ServerBuilder interface {
	WithRoute(pattern string, handler func(w http.ResponseWriter, r *http.Request)) ServerBuilder
	WithMiddleware(MiddlewareHandler) ServerBuilder
	WithMiddlewareFunc(func(next http.Handler) http.Handler) ServerBuilder
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
func (f *serverFixture) WithMiddleware(handler MiddlewareHandler) ServerBuilder {
	return f.WithMiddlewareFunc(handler.Handler)
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
		f.Log("trying to find free port from ports list to start the server")
		var listener net.Listener
		var err error
		for _, port := range f.ports {
			listener, err = net.Listen("tcp", "127.0.0.1:"+to.StringFromInteger(port))
			if err == nil && listener != nil {
				f.Log("starting server on port:", port)
				break
			}
		}
		require.NotNilf(f, listener, "failed to find free port from ports list %v", f.ports)

		server = &httptest.Server{
			Listener: listener,
			Config:   &http.Server{Handler: f.handler()},
		}
		server.Start()
	}

	cleanup = func() {
		server.Close()
	}
	return server, cleanup
}
