package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/internal/logging"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport/http"
)

// Middleware implements BRC-103/104 authentication
type Middleware struct {
	wallet               wallet.WalletInterface
	sessionManager       sessionmanager.SessionManagerInterface
	transport            transport.TransportInterface
	allowUnauthenticated bool
	logger               *slog.Logger
}

// ResponseRecorder is a custom ResponseWriter to capture response body and status
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       []byte
	written    bool
}

// WriteHeader writes status code
func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// Write writes response body to internal buffer
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.written {
		return 0, errors.New("response already written")
	}
	r.body = b
	r.written = true
	return len(b), nil
}

// New creates a new auth middleware
func New(opts Options) *Middleware {
	if opts.SessionManager == nil {
		opts.SessionManager = sessionmanager.NewSessionManager()
	}

	if opts.Wallet == nil {
		opts.Wallet = wallet.NewMockWallet(true, nil)
	}

	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}

	middlewareLogger := logging.Child(opts.Logger, "auth-middleware")

	middlewareLogger.Debug(" Creating new auth middleware")

	t := httptransport.New(opts.Wallet, opts.SessionManager, opts.AllowUnauthenticated, opts.Logger)

	middlewareLogger.Debug(" transport created")

	return &Middleware{
		wallet:               opts.Wallet,
		sessionManager:       opts.SessionManager,
		transport:            t,
		allowUnauthenticated: opts.AllowUnauthenticated,
		logger:               middlewareLogger,
	}
}

// Handler returns standard http middleware
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		if req.Method == http.MethodPost && req.URL.Path == "/.well-known/auth" {
			m.transport.HandleNonGeneralRequest(req, recorder, nil)

			_, err := recorder.ResponseWriter.Write(recorder.body)
			if err != nil {
				http.Error(recorder, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		req, authMsg, err := m.transport.HandleGeneralRequest(req, recorder, nil)
		if err != nil {
			http.Error(recorder, err.Error(), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(recorder, req)

		err = m.transport.HandleResponse(req, recorder, recorder.body, recorder.statusCode, authMsg)
		if err != nil {
			http.Error(recorder, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = recorder.ResponseWriter.Write(recorder.body)
		if err != nil {
			http.Error(recorder, err.Error(), http.StatusInternalServerError)
		}
	})
}
