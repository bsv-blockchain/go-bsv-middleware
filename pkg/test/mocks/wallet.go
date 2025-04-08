package mocks

import (
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// CreateServerMockWallet returns a mock wallet for server with predefined keys.
func CreateServerMockWallet(key *ec.PrivateKey) wallet.WalletInterface {
	return wallet.NewMockWallet(key, walletFixtures.DefaultNonces...)
}

// CreateClientMockWallet returns a mock wallet for server with predefined nonces.
func CreateClientMockWallet() wallet.WalletInterface {
	key, err := ec.PrivateKeyFromHex(walletFixtures.ClientPrivateKeyHex)
	if err != nil {
		panic(err)
	}
	return wallet.NewMockWallet(key, walletFixtures.ClientNonces...)
}
