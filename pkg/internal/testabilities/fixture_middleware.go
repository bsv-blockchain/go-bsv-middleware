package testabilities

import (
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/fixture"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/to"
	"github.com/stretchr/testify/require"
)

type MiddlewareFixtureOptions struct {
	logger *slog.Logger
}

func WithMiddlewareLogger(logger *slog.Logger) func(options *MiddlewareFixtureOptions) {
	return func(options *MiddlewareFixtureOptions) {
		options.logger = logger
	}
}

func WithoutLoggingFromMiddleware() func(*MiddlewareFixtureOptions) {
	return func(options *MiddlewareFixtureOptions) {
		options.logger = slog.New(slog.DiscardHandler)
	}
}

type MiddlewareFixture interface {
	NewAuth() *auth.Middleware
}

type middlewareFixture struct {
	testing.TB
	logger *slog.Logger
	wallet *wallet.TestWallet
}

func NewMiddlewareFixture(t testing.TB, opts ...func(*MiddlewareFixtureOptions)) MiddlewareFixture {
	f := &middlewareFixture{
		TB: t,
	}

	options := to.OptionsWithDefault(MiddlewareFixtureOptions{
		logger: logging.NewTestLogger(f),
	}, opts...)

	f.wallet = wallet.NewTestWallet(t, fixture.ServerIdentity.PrivateKey, wallet.WithTestWalletLogger(options.logger))
	f.logger = options.logger

	return f
}

func (f *middlewareFixture) NewAuth() *auth.Middleware {
	authMiddleware, err := auth.New(auth.Config{
		AllowUnauthenticated: false,
		Wallet:               f.wallet,
		Logger:               f.logger,
	})
	require.NoError(f, err)

	return authMiddleware
}
