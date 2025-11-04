package example_wallet

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/slogx"
	"github.com/go-softwarelab/common/pkg/testingx"
)

type (
	PrivateKeySource = wallet.PrivateKeySource
	PrivHex          = wallet.PrivHex
	WIF              = wallet.WIF
	ExampleWallet    = wallet.TestWallet
)

func New[KeySource PrivateKeySource](keySource KeySource) *ExampleWallet {
	return wallet.NewTestWallet(&testingx.E{Verbose: true}, keySource, wallet.WithTestWalletLogger(slogx.SilentLogger()))
}
