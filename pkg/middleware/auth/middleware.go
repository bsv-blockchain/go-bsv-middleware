package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/transport"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type contextKey string

const (
	requestKey  contextKey = "http_request"
	responseKey contextKey = "http_response"
	nextKey     contextKey = "http_next_handler"
)

// Middleware implements BRC-103/104 authentication
type Middleware struct {
	wallet               wallet.AuthOperations
	peer                 *auth.Peer
	sessionManager       auth.SessionManager
	transport            auth.Transport
	allowUnauthenticated bool
	logger               *slog.Logger
}

// New creates a new auth middleware
func New(opts Config) (*Middleware, error) {
	if opts.SessionManager == nil {
		opts.SessionManager = auth.NewSessionManager()
	}

	if opts.Wallet == nil {
		return nil, errors.New("wallet is required")
	}

	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}

	middlewareLogger := logging.Child(opts.Logger, "auth-middleware")

	if opts.OnCertificatesReceived == nil && opts.CertificatesToRequest != nil {
		return nil, errors.New("OnCertificatesReceived callback is required when certificates are requested")
	}

	if opts.OnCertificatesReceived != nil && opts.CertificatesToRequest == nil {
		return nil, errors.New("OnCertificatesReceived callback is set but no certificates are requested")
	}

	t := httptransport.New(opts.Wallet, opts.SessionManager, opts.AllowUnauthenticated, opts.Logger)
	peerCfg := &auth.PeerOptions{
		Wallet:         opts.Wallet,
		Transport:      t,
		SessionManager: opts.SessionManager,
		// TODO: add support for logger
		//Logger: opts.Logger
	}
	peer := auth.NewPeer(peerCfg)

	return &Middleware{
		peer:                 peer,
		wallet:               opts.Wallet,
		sessionManager:       opts.SessionManager,
		transport:            t,
		allowUnauthenticated: opts.AllowUnauthenticated,
		logger:               middlewareLogger,
	}, nil
}

// Handler returns a middleware handler function for BRC authentication
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrappedWriter := httptransport.WrapResponseWriter(w)

		ctx := context.WithValue(r.Context(), requestKey, r)
		ctx = context.WithValue(ctx, responseKey, wrappedWriter)

		ctx = context.WithValue(ctx, nextKey, func() {
			next.ServeHTTP(wrappedWriter, r)
		})

		m.logger.Debug("Processing request",
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method))

		authMsg, err := httptransport.ParseAuthMessageFromRequest(r)
		if err != nil {
			m.logger.Error("Failed to parse auth message", slog.String("error", err.Error()))
			http.Error(wrappedWriter, err.Error(), http.StatusBadRequest)
			return
		}

		if authMsg == nil {
			if m.allowUnauthenticated {
				r = r.WithContext(context.WithValue(r.Context(), transport.IdentityKey, "unknown"))
				next.ServeHTTP(wrappedWriter, r)
				return
			} else {
				// BRC-104 requires 401 for authentication failures
				http.Error(wrappedWriter, "Authentication required", http.StatusUnauthorized)
				return
			}
		}

		if authMsg.IdentityKey == nil && r.Header.Get("x-bsv-auth-identity-key") != "" {
			pubKey, err := ec.PublicKeyFromString(r.Header.Get("x-bsv-auth-identity-key"))
			if err != nil {
				m.logger.Error("Failed to parse identity key", slog.String("error", err.Error()))
				http.Error(wrappedWriter, "Invalid identity key format", http.StatusBadRequest)
				return
			}
			authMsg.IdentityKey = pubKey
		}

		callback, err := m.transport.GetRegisteredOnData()
		if err != nil {
			m.logger.Error("No message handler registered", slog.String("error", err.Error()))
			http.Error(wrappedWriter, "Server configuration error", http.StatusInternalServerError)
			return
		}

		err = callback(ctx, authMsg)
		if err != nil {
			m.logger.Error("Failed to process auth message", slog.String("error", err.Error()))

			statusCode := http.StatusInternalServerError
			errMsg := err.Error()

			switch {
			case errors.Is(err, auth.ErrNotAuthenticated):
				statusCode = http.StatusUnauthorized
				errMsg = "Authentication failed"
			case errors.Is(err, auth.ErrInvalidNonce):
				statusCode = http.StatusBadRequest
				errMsg = "Invalid nonce"
			case errors.Is(err, auth.ErrInvalidMessage):
				statusCode = http.StatusBadRequest
				errMsg = "Invalid message format"
			case errors.Is(err, auth.ErrSessionNotFound):
				statusCode = http.StatusUnauthorized
				errMsg = "Session not found"
			}

			http.Error(wrappedWriter, errMsg, statusCode)
			return
		}

		if !httptransport.HasBeenWritten(wrappedWriter) {
			if authMsg.IdentityKey != nil {
				r = r.WithContext(context.WithValue(r.Context(), transport.IdentityKey, authMsg.IdentityKey.ToDERHex()))
			}

			next.ServeHTTP(wrappedWriter, r)
		}
	})
}

// WithRequest adds a request to the context
func WithRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, requestKey, r)
}

// GetRequest gets a request from the context
func GetRequest(ctx context.Context) (*http.Request, bool) {
	r, ok := ctx.Value(requestKey).(*http.Request)
	return r, ok
}

// WithResponse adds a response writer to the context
func WithResponse(ctx context.Context, w http.ResponseWriter) context.Context {
	return context.WithValue(ctx, responseKey, w)
}

// GetResponse gets a response writer from the context
func GetResponse(ctx context.Context) (http.ResponseWriter, bool) {
	w, ok := ctx.Value(responseKey).(http.ResponseWriter)
	return w, ok
}

// WithNext adds a next handler function to the context
func WithNext(ctx context.Context, next func()) context.Context {
	return context.WithValue(ctx, nextKey, next)
}

// GetNext gets a next handler function from the context
func GetNext(ctx context.Context) (func(), bool) {
	next, ok := ctx.Value(nextKey).(func())
	return next, ok
}
