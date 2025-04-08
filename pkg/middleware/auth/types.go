package auth

import (
	"log/slog"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Options configures the auth middleware
type Options struct {
	Wallet               wallet.WalletInterface
	SessionManager       sessionmanager.SessionManagerInterface
	AllowUnauthenticated bool
	Logger               *slog.Logger
	PrivateKey           *ec.PrivateKey
}
