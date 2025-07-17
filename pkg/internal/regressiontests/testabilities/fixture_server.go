package testabilities

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

type ServerFixture interface {
	WithRoute(pattern string, handler func(w http.ResponseWriter, r *http.Request)) ServerFixture
	WithMiddleware(func(next http.Handler) http.Handler) ServerFixture
	Started() (serverURL *url.URL, cleanup func())
}

type serverFixture struct {
	testing.TB
	mux        *http.ServeMux
	middleware []middlewareFunc
}

type middlewareFunc func(next http.Handler) http.Handler

func newServerFixture(t testing.TB) ServerFixture {
	return &serverFixture{
		TB:         t,
		mux:        http.NewServeMux(),
		middleware: make([]middlewareFunc, 0),
	}
}

func (f *serverFixture) WithRoute(pattern string, handler func(w http.ResponseWriter, r *http.Request)) ServerFixture {
	f.mux.HandleFunc(pattern, handler)
	return f
}

// WithMiddleware adds a middleware function to the server fixture, wrapping the HTTP handler chain in the specified middleware.
// Middleware will be applied in opposite order - so the call chain will go from the first to the last.
func (f *serverFixture) WithMiddleware(middleware func(next http.Handler) http.Handler) ServerFixture {
	f.middleware = append(f.middleware, middleware)
	return f
}

func (f *serverFixture) Started() (serverURL *url.URL, cleanup func()) {
	var handler http.Handler = f.mux

	for i := len(f.middleware) - 1; i >= 0; i-- {
		handler = f.middleware[i](handler)
	}

	server := httptest.NewServer(handler)
	cleanup = func() {
		server.Close()
	}

	var err error
	serverURL, err = url.Parse(server.URL)
	require.NoErrorf(f, err, "failed to parse server URL (%s): invalid test setup", server.URL)

	return serverURL, cleanup
}
