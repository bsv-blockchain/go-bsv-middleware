package peer

import (
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

type Peer struct {
	wallet         wallet.WalletInterface
	transport      transport.TransportInterface
	sessionManager sessionmanager.SessionManagerInterface
}

func New(wallet wallet.WalletInterface, transport transport.TransportInterface, sessionManager sessionmanager.SessionManagerInterface) PeerInterface {
	return &Peer{
		wallet:         wallet,
		transport:      transport,
		sessionManager: sessionManager,
	}
}

func (p *Peer) HandleIncomingMessage(message transport.AuthMessage) {

}
