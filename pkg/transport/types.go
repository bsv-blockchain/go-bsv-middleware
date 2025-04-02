package transport

import (
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
)

const (
	// AuthVersion is the version of the authentication protocol.
	AuthVersion = "0.1"
	// IdentityKey is the key used to store the identity key in the context.
	IdentityKey = "identityKey"
	// RequestID is the key used to store the request ID in the context.
	RequestID = "requestID"
)

// Definition of the Message Types used in the authentication process.
const (
	InitialRequest      MessageType = "initialRequest"
	InitialResponse     MessageType = "initialResponse"
	CertificateRequest  MessageType = "certificateRequest"
	CertificateResponse MessageType = "certificateResponse"
	General             MessageType = "general"
)

// MessageType represents the type of message sent between peers during the authentication process.
type MessageType string

// AuthMessage represents a type message sent between peers during the authentication process.
type AuthMessage struct {
	Version               string                        `json:"version"`
	MessageType           MessageType                   `json:"messageType"`
	IdentityKey           string                        `json:"identityKey"`
	Nonce                 *string                       `json:"nonce,omitempty"`
	InitialNonce          string                        `json:"initialNonce"`
	YourNonce             *string                       `json:"yourNonce,omitempty"`
	Payload               *[]byte                       `json:"payload,omitempty"`
	Signature             *[]byte                       `json:"signature,omitempty"`
	Certificates          *wallet.VerifiableCertificate `json:"certificates"`
	RequestedCertificates RequestedCertificateSet       `json:"requestedCertificates"`
}

// RequestedCertificateSet represents the set of certificates requested by a peer.
type RequestedCertificateSet struct {
	Certifiers []string            `json:"certifiers"`
	Types      map[string][]string `json:"types"`
}

// OnCertificatesReceivedFunc callback type for handling received certificates
type OnCertificatesReceivedFunc func(
	senderPublicKey string,
	certs []any,
	req *http.Request,
	res http.ResponseWriter,
	next func(),
)

// MessageCallback is a callback function for handling messages. Placeholder for now.
type MessageCallback func(message AuthMessage) error

// MessageTypeFromString returns a MessageType from a string.
func (m *MessageType) String() string {
	return string(*m)
}

// Empty checks if the RequestedCertificateSet is empty.
func (rc *RequestedCertificateSet) Empty() bool {
	if rc.Certifiers != nil || len(rc.Certifiers) > 0 {
		return false
	}

	if rc.Types != nil || len(rc.Types) > 0 {
		return false
	}

	return true
}

// String returns a string representation of the RequestedCertificateSet.
func (rc *RequestedCertificateSet) String() string {
	if rc.Empty() {
		return ""
	}

	return rc.String()
}
