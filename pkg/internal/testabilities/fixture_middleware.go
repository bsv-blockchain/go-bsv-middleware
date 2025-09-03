package testabilities

import (
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/fixture"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/to"
)

type MiddlewareFixtureOptions struct {
	logger *slog.Logger
}

func WithMiddlewareLogger(logger *slog.Logger) func(options *MiddlewareFixtureOptions) {
	return func(options *MiddlewareFixtureOptions) {
		options.logger = logger
	}
}

type MiddlewareFixture interface {
	NewAuth() *middleware.AuthMiddlewareFactory
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

func (f *middlewareFixture) NewAuth() *middleware.AuthMiddlewareFactory {
	return middleware.NewAuth(f.wallet, middleware.WithAuthLogger(f.logger))
}
