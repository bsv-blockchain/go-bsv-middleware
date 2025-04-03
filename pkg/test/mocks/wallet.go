package mocks

import (
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
)

// CreateServerMockWallet returns a mock wallet for server with predefined keys.
func CreateServerMockWallet() wallet.WalletInterface {
	return wallet.NewMockWallet(true, &walletFixtures.ServerIdentityKey, walletFixtures.DefaultNonces...)
}

// CreateClientMockWallet returns a mock wallet for server with predefined keys.
func CreateClientMockWallet() wallet.WalletInterface {
	return wallet.NewMockWallet(true, &walletFixtures.ClientIdentityKey, walletFixtures.ClientNonces...)
}
