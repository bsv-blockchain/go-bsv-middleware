package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Middleware is transport-agnostic - only uses auth.Transport interface
type Middleware struct {
	peer                 *auth.Peer
	wallet               wallet.Interface
	sessionManager       auth.SessionManager
	transport            auth.Transport
	allowUnauthenticated bool
	logger               *slog.Logger
}

// New creates a new instance of the auth middleware.
func New(cfg Config) (*Middleware, error) {
	if cfg.Wallet == nil {
		return nil, errors.New("wallet is required")
	}

	if cfg.Transport == nil {
		return nil, errors.New("transport is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	middlewareLogger := logging.Child(logger, "auth-middleware")

	sessionManager := cfg.SessionManager
	if sessionManager == nil {
		sessionManager = auth.NewSessionManager()
	}

	if cfg.OnCertificatesReceived == nil && cfg.CertificatesToRequest != nil {
		return nil, errors.New("OnCertificatesReceived callback is required when certificates are requested")
	}

	if cfg.OnCertificatesReceived != nil && cfg.CertificatesToRequest == nil {
		return nil, errors.New("OnCertificatesReceived callback is set but no certificates are requested")
	}

	peerCfg := &auth.PeerOptions{
		Wallet:                cfg.Wallet,
		Transport:             cfg.Transport,
		SessionManager:        sessionManager,
		CertificatesToRequest: cfg.CertificatesToRequest,
	}
	peer := auth.NewPeer(peerCfg)
	peer.ListenForCertificatesReceived(cfg.OnCertificatesReceived)

	return &Middleware{
		peer:                 peer,
		wallet:               cfg.Wallet,
		sessionManager:       sessionManager,
		transport:            cfg.Transport,
		allowUnauthenticated: cfg.AllowUnauthenticated,
		logger:               middlewareLogger,
	}, nil
}

// ProcessAuthentication is the core business logic
func (m *Middleware) ProcessAuthentication(ctx context.Context, authMsg *auth.AuthMessage) error {
	if authMsg == nil {
		if m.allowUnauthenticated {
			return nil
		} else {
			return errors.New("authentication required")
		}
	}

	callback, err := m.transport.GetRegisteredOnData()
	if err != nil {
		return errors.New("server configuration error")
	}

	if err := callback(ctx, authMsg); err != nil {
		m.logger.Error("Failed to process auth message", slog.String("error", err.Error()))
		return err
	}

	return nil
}

// GetPeer returns the peer associated with this middleware.
func (m *Middleware) GetPeer() *auth.Peer {
	return m.peer
}

// GetTransport returns the transport used by this middleware.
func (m *Middleware) GetTransport() auth.Transport {
	return m.transport
}

// GetSessionManager returns the session manager used by this middleware.
func (m *Middleware) GetSessionManager() auth.SessionManager {
	return m.sessionManager
}

// IsAuthenticationRequired checks if authentication is required for this middleware.
func (m *Middleware) IsAuthenticationRequired() bool {
	return !m.allowUnauthenticated
}
