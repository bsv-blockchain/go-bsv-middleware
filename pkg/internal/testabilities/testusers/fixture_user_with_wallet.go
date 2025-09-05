package testusers

import (
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
	"github.com/go-softwarelab/common/pkg/slogx"
	"github.com/go-softwarelab/common/pkg/to"
)

type UserWithWalletOptions struct {
	logger *slog.Logger
}

func WithLogger(logger *slog.Logger) func(options *UserWithWalletOptions) {
	return func(options *UserWithWalletOptions) {
		options.logger = logger
	}
}

func WithoutLogging() func(*UserWithWalletOptions) {
	return func(options *UserWithWalletOptions) {
		options.logger = slog.New(slog.DiscardHandler)
	}
}

type UserWithWallet struct {
	User
	wallet      *wallet.TestWallet
	certManager *testcertificates.Manager
}

// NewAlice creates new Alice with wallet (as UserWithWallet) that can be used in tests..
func NewAlice(t testing.TB, opts ...func(*UserWithWalletOptions)) *UserWithWallet {
	return newUserWithWallet(t, Alice, opts...)
}

func newUserWithWallet(t testing.TB, user User, opts ...func(*UserWithWalletOptions)) *UserWithWallet {
	options := to.OptionsWithDefault(UserWithWalletOptions{
		logger: slogx.NewTestLogger(t),
	}, opts...)

	logger := options.logger.With("actor", user.Name)

	userWallet := wallet.NewTestWallet(t, wallet.PrivHex(user.PrivKey), wallet.WithTestWalletLogger(logger))
	userCertManager := testcertificates.NewManager(t, userWallet)

	return &UserWithWallet{
		User:        user,
		wallet:      userWallet,
		certManager: userCertManager,
	}
}

func (u *UserWithWallet) Wallet() *wallet.TestWallet {
	return u.wallet
}

func (u *UserWithWallet) CertManager() *testcertificates.Manager {
	return u.certManager
}
