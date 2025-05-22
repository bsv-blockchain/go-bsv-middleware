package transport

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var (
	// DefaultAuthProtocol is the default protocol for authentication messages.
	DefaultAuthProtocol = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: auth.AUTH_PROTOCOL_ID}
)

type AuthMessageHandler func(context.Context, *auth.AuthMessage) error
