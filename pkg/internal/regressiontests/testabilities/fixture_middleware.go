package testabilities

import (
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/testabilities/fixture"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

type MiddlewareFixture interface {
	NewAuth() *auth.Middleware
}

type middlewareFixture struct {
	testing.TB
	logger *slog.Logger
	wallet *wallet.CompletedProtoWallet
}

func newMiddlewareFixture(t testing.TB) MiddlewareFixture {
	wallet, err := wallet.NewCompletedProtoWallet(fixture.ServerIdentity.PrivateKey)
	require.NoError(t, err, "failed to create wallet: invalid test setup")

	f := &middlewareFixture{
		TB:     t,
		wallet: wallet,
	}

	f.logger = logging.NewTestLogger(f)

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
