package transport

import "net/http"

// TransportInterface define mechanism used for sending and receiving messages.
type TransportInterface interface { //nolint:revive // This is an interface, so it's fine to use the name "SessionManagerInterface".
	// Send Sends an AuthMessage to the connected Peer.
	Send(message AuthMessage) error

	// OnData Stores the callback bound by a Peer
	OnData(callback func(message AuthMessage) error) error

	// HandleNonGeneralRequest Handles an incoming request with non-general message types, manages peer-to-peer certificate handling,
	// and modifies the response object to enable custom behaviors like certificate requests and tailored responses.
	HandleNonGeneralRequest(req *http.Request, res http.ResponseWriter) error

	// HandleGeneralRequest Handles an general incoming request, validates the request, and modifies the response to contain auth headers.
	HandleGeneralRequest(req *http.Request, res http.ResponseWriter) (*http.Request, *AuthMessage, error)

	// HandleResponse sets up auth headers in the response object and generate signature for whole response.
	HandleResponse(req *http.Request, res http.ResponseWriter, body []byte, status int, msg *AuthMessage) error
}
