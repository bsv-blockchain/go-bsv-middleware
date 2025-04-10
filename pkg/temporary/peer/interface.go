package peer

import (
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

// Peer represents a participant in a mutual authentication protocol.
type Peer interface {
	// ToPeer sends a message to a specific peer identified by their identity key.
	ToPeer(message []byte, identityKey string, maxWaitTime int) error

	// RequestCertificates requests specific certificates from a peer.
	RequestCertificates(certificatesToRequest transport.RequestedCertificateSet, identityKey string, maxWaitTime int) error

	// GetAuthenticatedSession retrieves an authenticated session for a given peer identity.
	GetAuthenticatedSession(identityKey string, maxWaitTime int) (*sessionmanager.PeerSession, error)

	// SendCertificateResponse sends certificates to a peer in response to a certificate request.
	SendCertificateResponse(verifierIdentityKey string, certificates []wallet.VerifiableCertificate) error

	// ListenForGeneralMessages registers a callback for receiving general messages.
	ListenForGeneralMessages(callback func(senderPublicKey string, payload []byte)) int

	// StopListeningForGeneralMessages removes a general message listener.
	StopListeningForGeneralMessages(callbackID int)

	// ListenForCertificatesReceived registers a callback for receiving certificates.
	ListenForCertificatesReceived(callback func(senderPublicKey string, certs []wallet.VerifiableCertificate)) int

	// StopListeningForCertificatesReceived removes a certificate received listener.
	StopListeningForCertificatesReceived(callbackID int)

	// ListenForCertificatesRequested registers a callback for certificate requests.
	ListenForCertificatesRequested(callback func(senderPublicKey string, requestedCertificates transport.RequestedCertificateSet)) int

	// StopListeningForCertificatesRequested removes a certificate request listener.
	StopListeningForCertificatesRequested(callbackID int)
}
