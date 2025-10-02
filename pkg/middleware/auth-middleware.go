package middleware

import (
	"log/slog"
	"net/http"
	"slices"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/authentication"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// AuthMiddlewareConfig configures the auth middleware
type AuthMiddlewareConfig = authentication.Config

// WithAuthAllowUnauthenticatedValue allows to configure if middleware should allow for unauthenticated requests or not, based on provided boolean.
func WithAuthAllowUnauthenticatedValue(allowUnauthenticated bool) func(*AuthMiddlewareConfig) {
	return func(cfg *AuthMiddlewareConfig) {
		cfg.AllowUnauthenticated = allowUnauthenticated
	}
}

// WithAuthAllowUnauthenticated configures the middleware to allow for unauthenticated requests.
func WithAuthAllowUnauthenticated() func(*AuthMiddlewareConfig) {
	return WithAuthAllowUnauthenticatedValue(true)
}

// WithAuthDisallowUnauthenticated configures the middleware to disallow for unauthenticated requests.
func WithAuthDisallowUnauthenticated() func(*AuthMiddlewareConfig) {
	return WithAuthAllowUnauthenticatedValue(false)
}

// WithAuthSessionManager configures the middleware to use the provided session manager.
func WithAuthSessionManager(sessionManager auth.SessionManager) func(*AuthMiddlewareConfig) {
	// don't override the default
	if sessionManager == nil {
		return func(cfg *AuthMiddlewareConfig) {}
	}

	return func(cfg *AuthMiddlewareConfig) {
		cfg.SessionManager = sessionManager
	}
}

// WithAuthLogger configures the middleware to use the provided logger.
func WithAuthLogger(logger *slog.Logger) func(*AuthMiddlewareConfig) {
	// don't override the default
	if logger == nil {
		return func(cfg *AuthMiddlewareConfig) {}
	}

	return func(cfg *AuthMiddlewareConfig) {
		cfg.Logger = logger
	}
}

// WithAuthCertificatesToRequest configures the middleware to request for provided certificates set on handshake phase of authentication.
func WithAuthCertificatesToRequest(certificatesToRequest *utils.RequestedCertificateSet) func(*AuthMiddlewareConfig) {
	return func(cfg *AuthMiddlewareConfig) {
		cfg.CertificatesToRequest = certificatesToRequest
	}
}

// WithAuthCertificatesReceivedListener allows for providing custom listener for received certificates.
func WithAuthCertificatesReceivedListener(listener auth.OnCertificateReceivedCallback) func(config *AuthMiddlewareConfig) {
	return func(cfg *AuthMiddlewareConfig) {
		cfg.OnCertificatesReceived = listener
	}
}

// AuthMiddlewareFactory is a factory for auth middleware.
type AuthMiddlewareFactory struct {
	wallet  wallet.Interface
	options []func(*AuthMiddlewareConfig)
}

// NewAuth creates a new auth middleware factory, which can be used to apply auth middleware to a server.
func NewAuth(wallet wallet.Interface, opts ...func(*AuthMiddlewareConfig)) *AuthMiddlewareFactory {
	if wallet == nil {
		panic("wallet must be provided to create auth middleware")
	}

	return &AuthMiddlewareFactory{
		wallet:  wallet,
		options: opts,
	}
}

// HTTPHandler creates a new auth middleware as http.Handler, which wraps the provided handler.
func (f *AuthMiddlewareFactory) HTTPHandler(next http.Handler) http.Handler {
	return f.HTTPHandlerWithOptions(next)
}

// HTTPHandlerWithOptions creates a new auth middleware as http.Handler, which wraps the provided handler.
// Allows for additional configuration with options.
//
// This method can be useful when we have factory with default configuration for middleware,
// but we want to customize it for a specific handler (for example, turn on unauthenticated access).
func (f *AuthMiddlewareFactory) HTTPHandlerWithOptions(next http.Handler, opts ...func(*AuthMiddlewareConfig)) http.Handler {
	opts = append(slices.Clone(f.options), opts...)

	if f.wallet == nil {
		// In case if someone would create a factory just by calling &middleware.AuthMiddlewareFactory{}
		panic("wallet must be provided to create auth middleware")
	}

	if next == nil {
		panic("next handler must be provided to apply auth middleware to it")
	}

	return authentication.NewMiddleware(next, f.wallet, opts...)
}
