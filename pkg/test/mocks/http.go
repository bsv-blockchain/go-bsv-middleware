package mocks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/internal/logging"
	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/require"
)

type MockHTTPServer struct {
	mux                  *http.ServeMux
	server               *httptest.Server
	allowUnauthenticated bool
	logger               *slog.Logger
}

func CreateMockHTTPServer() *MockHTTPServer {
	mux := http.NewServeMux()
	mux.Handle("/", indexHandler())
	mux.Handle("/ping", pingHandler())
	return &MockHTTPServer{mux: mux}
}

func (s *MockHTTPServer) WithMiddleware() *MockHTTPServer {
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}

	opts := auth.Options{
		AllowUnauthenticated: s.allowUnauthenticated,
		Logger:               s.logger,
		Wallet:               CreateServerMockWallet(),
	}
	middleware := auth.New(opts)

	handlerWithMiddleware := middleware.Handler(s.mux)

	s.server = httptest.NewServer(handlerWithMiddleware)
	time.Sleep(1 * time.Second)

	return s
}

func (s *MockHTTPServer) WithoutMiddleware() *MockHTTPServer {
	s.server = httptest.NewServer(s.mux)
	return s
}

func (s *MockHTTPServer) WithAllowUnauthenticated() *MockHTTPServer {
	s.allowUnauthenticated = true
	return s
}

func (s *MockHTTPServer) WithLogger() *MockHTTPServer {
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)
	s.logger = logging.Child(logger, "tests")
	return s
}

func (s *MockHTTPServer) Close() {
	s.server.Close()
}

func (s *MockHTTPServer) URL() string {
	return s.server.URL
}

func (s *MockHTTPServer) SendNonGeneralRequest(t *testing.T, msg *transport.AuthMessage) (*http.Response, error) {
	authURL := s.URL() + "/.well-known/auth"
	authMethod := "POST"

	dataBytes, err := json.Marshal(msg)
	require.Nil(t, err)

	response := prepareAndCallRequest(t, authMethod, authURL, nil, dataBytes)

	return response, nil
}

func (s *MockHTTPServer) SendGeneralRequest(t *testing.T, method, path string, headers map[string]string, body any) (*http.Response, error) {
	url := s.URL() + path

	var dataBytes []byte
	var err error
	if body != nil {
		dataBytes, err = json.Marshal(body)
		require.Nil(t, err)
	}

	response := prepareAndCallRequest(t, method, url, headers, dataBytes)

	return response, nil
}

func indexHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func pingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Pong!"))
	})
}

func prepareAndCallRequest(t *testing.T, method, authURL string, headers map[string]string, jsonData []byte) *http.Response {
	req, err := http.NewRequest(method, authURL, bytes.NewBuffer(jsonData))
	require.Nil(t, err)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	response, err := client.Do(req)
	require.Nil(t, err)

	return response
}

func MapBodyToAuthMessage(t *testing.T, response *http.Response) (*transport.AuthMessage, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.Nil(t, err)

	var authMessage *transport.AuthMessage
	if err = json.Unmarshal(body, &authMessage); err != nil {
		return nil, errors.New("failed to unmarshal response")
	}

	return authMessage, nil
}
