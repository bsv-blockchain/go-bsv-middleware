package transport

import (
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/temporary/wallet"
)

type contextKey string

const (
	// AuthVersion is the version of the authentication protocol.
	AuthVersion = "0.1"
	// IdentityKey is the key used to store the identity key in the context.
	IdentityKey contextKey = "identity"
	// RequestID is the key used to store the request ID in the context.
	RequestID contextKey = "requestID"
)

// RequestedCertificateSet represents the set of certificates requested by a peer.
type RequestedCertificateSet struct {
	Certifiers []string            `json:"certifiers"`
	Types      map[string][]string `json:"types"`
}

// OnCertificatesReceivedFunc callback type for handling received certificates
type OnCertificatesReceivedFunc func(
	senderPublicKey string,
	certs *[]wallet.VerifiableCertificate,
	req *http.Request,
	res http.ResponseWriter,
	next func(),
)
