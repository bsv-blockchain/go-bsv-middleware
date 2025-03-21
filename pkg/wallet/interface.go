package wallet

import "context"

// GetPublicKeyOptions defines parameters for GetPublicKey
type GetPublicKeyOptions struct {
	// IdentityKey is a flag to return the identity key
	IdentityKey bool `json:"identityKey"`
	// ProtocolID is the protocol ID for the key
	ProtocolID any `json:"protocolID,omitempty"`
	// KeyID is the key ID for the key
	KeyID string `json:"keyID,omitempty"`
	// Counterparty is the counterparty for the key
	Counterparty string `json:"counterparty,omitempty"`
	// Privileged is a flag to return a privileged key
	Privileged bool `json:"privileged,omitempty"`
	// ForSelf is a flag to return a key for self
	ForSelf bool `json:"forSelf,omitempty"`
}

// Interface defines the core functionality needed for authentication
type Interface interface {
	// GetPublicKey returns a public key
	GetPublicKey(ctx context.Context, options GetPublicKeyOptions) (string, error)

	// CreateSignature signs data with specific protocol/key IDs
	CreateSignature(ctx context.Context, data []byte, protocolID any, keyID string, counterparty string) ([]byte, error)

	// VerifySignature verifies a signature
	VerifySignature(ctx context.Context, data []byte, signature []byte, protocolID any, keyID string, counterparty string) (bool, error)

	// CreateNonce creates a nonce for challenge-response authentication
	CreateNonce(ctx context.Context) (string, error)

	// VerifyNonce verifies a nonce that was previously created
	VerifyNonce(ctx context.Context, nonce string) (bool, error)

	// ListCertificates is a stub for future certificate functionality
	ListCertificates(ctx context.Context, certifiers []string, types []string) ([]Certificate, error)

	// ProveCertificate is a stub for future certificate functionality
	ProveCertificate(ctx context.Context, certificate Certificate, verifier string, fieldsToReveal []string) (map[string]string, error)
}

// Certificate is a placeholder for the certificate data structure
type Certificate struct {
	// Type is the type of certificate
	Type string `json:"type"`
	// Subject is the subject of the certificate
	Subject string `json:"subject"`
	// SerialNumber is the serial number of the certificate
	SerialNumber string `json:"serialNumber"`
	// Certifier is the certifier of the certificate
	Certifier string `json:"certifier"`
	// RevocationOutpoint is the revocation outpoint of the certificate
	RevocationOutpoint string `json:"revocationOutpoint"`
	// Fields is the map representing custom fields of the certificate (payload)
	Fields map[string]interface{} `json:"fields"`
	// Signature is the signature of the certificate
	Signature string `json:"signature"`
}
