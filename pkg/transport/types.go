package transport

import (
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
)

// AuthVersion is the version of the authentication protocol.
const AuthVersion = "0.1"

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
	Version               string                  `json:"version"`
	MessageType           MessageType             `json:"messageType"`
	IdentityKey           string                  `json:"identityKey"`
	Nonce                 *string                 `json:"nonce,omitempty"`
	InitialNonce          string                  `json:"initialNonce"`
	YourNonce             *string                 `json:"yourNonce,omitempty"`
	Payload               *[]byte                 `json:"payload,omitempty"`
	Signature             *[]byte                 `json:"signature,omitempty"`
	Certificates          *[]wallet.Certificate   `json:"certificates"`
	RequestedCertificates RequestedCertificateSet `json:"requestedCertificates"`
}

type RequestedCertificateSet struct {
	Certifiers []string            `json:"certifiers"`
	Types      map[string][]string `json:"types"`
}

// OnCertificatesReceivedFunc callback type for handling received certificates
type OnCertificatesReceivedFunc func(
	senderPublicKey string,
	// TODO: update type
	certs []any,
	req *http.Request,
	res http.ResponseWriter,
	next func(),
)

type MessageCallback func(message AuthMessage) error

func (m *MessageType) String() string {
	return string(*m)
}
