package testabilities

import (
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/go-softwarelab/common/pkg/slogx"
	"github.com/go-softwarelab/common/pkg/to"
)

type ClientFixtureOptions struct {
	logger *slog.Logger
}

func WithClientLogger(logger *slog.Logger) func(options *ClientFixtureOptions) {
	return func(options *ClientFixtureOptions) {
		options.logger = logger
	}
}

type ClientFixture interface {
	ForUser(*testusers.UserWithWallet) (client *clients.AuthFetch, cleanup func())
}

type clientFixture struct {
	testing.TB
	logger *slog.Logger
}

func newClientFixture(t testing.TB, opts ...func(*ClientFixtureOptions)) ClientFixture {
	f := &clientFixture{
		TB: t,
	}

	options := to.OptionsWithDefault(ClientFixtureOptions{
		logger: slogx.NewTestLogger(f),
	}, opts...)

	f.logger = options.logger

	return f
}

func (f *clientFixture) ForUser(user *testusers.UserWithWallet) (client *clients.AuthFetch, cleanup func()) {
	userWallet := user.Wallet()
	return clients.New(userWallet, clients.WithLogger(f.logger)), func() {}
}
