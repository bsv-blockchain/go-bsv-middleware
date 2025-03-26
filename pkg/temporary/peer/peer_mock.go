package peer

import (
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

type Peer struct {
	wallet         wallet.Interface
	transport      transport.Interface
	sessionManager sessionmanager.Interface
}

func New(wallet wallet.Interface, transport transport.Interface, sessionManager sessionmanager.Interface) Interface {
	return &Peer{
		wallet:         wallet,
		transport:      transport,
		sessionManager: sessionManager,
	}
}

func (p *Peer) HandleIncomingMessage(message transport.AuthMessage) {

}
