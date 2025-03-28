package peer

import "github.com/4chain-ag/go-bsv-middleware/pkg/transport"

type PeerInterface interface {
	// HandleIncomingMessage Handles incoming messages from the transport.
	HandleIncomingMessage(message transport.AuthMessage)
}
