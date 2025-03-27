package auth

import (
	"log/slog"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport/http"
)

const logHeader = "AUTH MIDDLEWARE"

// Middleware implements BRC-103/104 authentication
type Middleware struct {
	wallet         wallet.Interface
	sessionManager sessionmanager.Interface
	transport      transport.Interface
	//peer                 peer.Interface
	allowUnauthenticated bool
	logger               *slog.Logger
}

// New creates a new auth middleware
func New(opts Options) *Middleware {
	// Use mocked session manager if not provided
	if opts.SessionManager == nil {
		opts.SessionManager = sessionmanager.NewSessionManager()
	}

	// Use mocked wallet if not provided
	if opts.Wallet == nil {
		opts.Wallet = wallet.NewMockWallet(true, nil)
	}

	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}

	middlewareLogger := opts.Logger.With("service", "AUTH MIDDLEWARE")

	middlewareLogger.Debug(" Creating new auth middleware")

	t := httptransport.New(opts.Wallet, opts.SessionManager, opts.AllowUnauthenticated, opts.Logger)
	//p := peer.New(opts.Wallet, t, opts.SessionManager)

	middlewareLogger.Debug(logHeader + " transport created")

	return &Middleware{
		wallet:         opts.Wallet,
		sessionManager: opts.SessionManager,
		transport:      t,
		//peer:                 p,
		allowUnauthenticated: opts.AllowUnauthenticated,
		logger:               middlewareLogger,
	}
}

// Handler returns standard http middleware
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost && req.URL.Path == "/.well-known/auth" {
			m.transport.HandleNonGeneralRequest(req, w, nil)
			return
		}

		err := m.transport.HandleGeneralRequest(req, w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, req)
	})
}
