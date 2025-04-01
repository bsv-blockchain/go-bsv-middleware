package mocks

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/require"
)

type MockHTTPServer struct {
	mux                  *http.ServeMux
	server               *http.Server
	allowUnauthenticated bool
}

func CreateMockHTTPServer() *MockHTTPServer {
	mux := http.NewServeMux()
	mux.Handle("/", indexHandler())
	mux.Handle("/ping", pingHandler())
	return &MockHTTPServer{mux: mux}
}

func (s *MockHTTPServer) WithMiddleware() *MockHTTPServer {
	logger := slog.New(slog.DiscardHandler)

	opts := auth.Options{
		AllowUnauthenticated: s.allowUnauthenticated,
		Logger:               logger,
		Wallet:               CreateServerMockWallet(),
	}
	middleware := auth.New(opts)

	handlerWithMiddleware := middleware.Handler(s.mux)

	s.server = &http.Server{Addr: ":8080", Handler: handlerWithMiddleware}

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		}
	}()
	time.Sleep(1 * time.Second)

	return s
}

func (s *MockHTTPServer) WithoutMiddleware() *MockHTTPServer {
	//s.server = httptest.NewServer(s.mux)
	s.server = &http.Server{Handler: s.mux}
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		}
	}()
	time.Sleep(1 * time.Second)
	return s
}

func (s *MockHTTPServer) WithAllowUnauthenticated() *MockHTTPServer {
	s.allowUnauthenticated = true
	return s
}

func (s *MockHTTPServer) Close() {
	s.server.Close()
}

func (s *MockHTTPServer) URL() string {
	return s.server.Addr
}

func (s *MockHTTPServer) SendNonGeneralRequest(t *testing.T, msg *transport.AuthMessage) (*http.Response, *transport.AuthMessage, error) {
	//authURL := s.server.Addr + "/.well-known/auth"
	authURL := "http://localhost:8080/.well-known/auth"
	authMethod := "POST"

	dataBytes, err := json.Marshal(msg)
	require.Nil(t, err)

	response := prepareAndCallRequest(t, authMethod, authURL, nil, dataBytes)
	responseAuthMsg := mapResponseToAuthMessage(t, response)

	return response, responseAuthMsg, nil
}

func (s *MockHTTPServer) SendGeneralRequest(t *testing.T, method, path string, headers map[string]string, body any) (*http.Response, error) {
	//url := s.server.Addr + path
	url := "http://localhost:8080" + path

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

func mapResponseToAuthMessage(t *testing.T, response *http.Response) *transport.AuthMessage {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.Nil(t, err)

	var responseData *transport.AuthMessage
	if err = json.Unmarshal(body, &responseData); err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}

	return responseData
}
