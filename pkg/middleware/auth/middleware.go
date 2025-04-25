package auth

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/wallet"
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

// ResponseRecorder is a custom ResponseWriter to capture response body and status
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
	written    bool
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}
}

// WriteHeader writes status code
func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
}

// Write writes response body to internal buffer
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.written {
		return 0, errors.New("response already written")
	}

	n, err := r.body.Write(b)
	if err != nil {
		return 0, errors.New("failed to write response")
	}

	r.written = true
	return n, nil
}

// Finalize writes the captured headers and body
func (r *responseRecorder) Finalize() error {
	r.ResponseWriter.WriteHeader(r.statusCode)
	body := strings.TrimSpace(r.body.String())
	_, err := r.ResponseWriter.Write([]byte(body))
	if err != nil {
		return errors.New("failed to write response")
	}

	return nil
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

	t := httptransport.New(opts.Wallet, opts.SessionManager, opts.AllowUnauthenticated, opts.Logger, opts.CertificatesToRequest, opts.OnCertificatesReceived)
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

// Handler returns standard http middleware
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		// write response writer
		// write req
		// write next

		msg := &auth.AuthMessage{}

		callback, _ := m.transport.GetRegisteredOnData()
		err := callback(ctx, msg)
		if err != nil {
			m.logger.Error("failed to handle auth message", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func createResponse(recorder *responseRecorder) {
	err := recorder.Finalize()
	if err != nil {
		http.Error(recorder, err.Error(), http.StatusInternalServerError)
		return
	}
}
