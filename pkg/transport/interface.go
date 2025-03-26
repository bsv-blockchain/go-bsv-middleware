package transport

import "net/http"

// Interface define mechanism used for sending and receiving messages.
type Interface interface {
	// Send Sends an AuthMessage to the connected Peer.
	Send(message AuthMessage)
	// OnData Stores the callback bound by a Peer
	OnData(callback MessageCallback)
	// HandleNonGeneralRequest Handles an incoming request for the server.
	// This method processes both general and non-general message types, manages peer-to-peer certificate handling,
	// and modifies the response object to enable custom behaviors like certificate requests and tailored responses.
	HandleNonGeneralRequest(req *http.Request, res http.ResponseWriter, onCertificatesReceived OnCertificatesReceivedFunc)
	HandleGeneralRequest(req *http.Request, res http.ResponseWriter, onCertificatesReceived OnCertificatesReceivedFunc) error
}

//// SetPeer Assign the peer for the transport
//SetPeer(peer shared.PeerInterface)
