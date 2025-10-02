package testabilities

import (
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/fixture"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/slogx"
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
	NewAuth(opts ...func(*middleware.AuthMiddlewareConfig)) *middleware.AuthMiddlewareFactory
	NewPayment(opts ...func(*middleware.PaymentMiddlewareConfig)) *middleware.PaymentMiddlewareFactory
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
		logger: slogx.NewTestLogger(f),
	}, opts...)

	f.wallet = wallet.NewTestWallet(t, fixture.ServerIdentity.PrivateKey, wallet.WithTestWalletLogger(options.logger))
	f.wallet.OnInternalizeAction().Return(&wallet.InternalizeActionResult{Accepted: true}, nil)
	f.logger = options.logger

	return f
}

func (f *middlewareFixture) NewAuth(opts ...func(*middleware.AuthMiddlewareConfig)) *middleware.AuthMiddlewareFactory {
	opts = append(opts, middleware.WithAuthLogger(f.logger))
	return middleware.NewAuth(f.wallet, opts...)
}

func (f *middlewareFixture) NewPayment(opts ...func(*middleware.PaymentMiddlewareConfig)) *middleware.PaymentMiddlewareFactory {
	opts = append(opts, middleware.WithPaymentLogger(f.logger))
	return middleware.NewPayment(f.wallet, opts...)
}
