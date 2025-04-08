package wallet

import (
	"context"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// WalletInterface defines the core functionality needed for authentication
type WalletInterface interface { //nolint:revive // This is an interface, so it's fine to use the name "WalletInterface".
	// GetPublicKey returns a public key
	GetPublicKey(args *GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)

	// CreateSignature signs data with specific protocol/key IDs
	CreateSignature(args *CreateSignatureArgs, originator string) (*CreateSignatureResult, error)

	// VerifySignature verifies a signature
	VerifySignature(args *VerifySignatureArgs) (*VerifySignatureResult, error)

	// CreateNonce creates a nonce for challenge-response authentication
	CreateNonce(ctx context.Context) (string, error)

	// VerifyNonce verifies a nonce that was previously created
	VerifyNonce(ctx context.Context, nonce string) (bool, error)

	// ListCertificates is a stub for future certificate functionality
	ListCertificates(ctx context.Context, certifiers []string, types []string) ([]Certificate, error)

	// ProveCertificate is a stub for future certificate functionality
	ProveCertificate(ctx context.Context, certificate Certificate, verifier string, fieldsToReveal []string) (map[string]string, error)
}

//// WalletInterface defines the core functionality needed for authentication
//type WalletInterface interface { //nolint:revive // This is an interface, so it's fine to use the name "WalletInterface".
//	// GetPublicKey returns a public key
//	GetPublicKey(ctx context.Context, options GetPublicKeyOptions) (string, error)
//
//	// CreateSignature signs data with specific protocol/key IDs
//	CreateSignature(ctx context.Context, data []byte, protocolID any, keyID string, counterparty string) ([]byte, error)
//
//	// VerifySignature verifies a signature
//	VerifySignature(ctx context.Context, data []byte, signature []byte, protocolID any, keyID string, counterparty string) (bool, error)
//
//	// CreateNonce creates a nonce for challenge-response authentication
//	CreateNonce(ctx context.Context) (string, error)
//
//	// VerifyNonce verifies a nonce that was previously created
//	VerifyNonce(ctx context.Context, nonce string) (bool, error)
//
//	// ListCertificates is a stub for future certificate functionality
//	ListCertificates(ctx context.Context, certifiers []string, types []string) ([]Certificate, error)
//
//	// ProveCertificate is a stub for future certificate functionality
//	ProveCertificate(ctx context.Context, certificate Certificate, verifier string, fieldsToReveal []string) (map[string]string, error)
//}

type keyDeriverInterface interface {
	DerivePrivateKey(protocol Protocol, keyID string, counterparty Counterparty) (*ec.PrivateKey, error)
	//DerivePublicKey(protocol Protocol, keyID string, counterparty Counterparty, forSelf bool) (*ec.PublicKey, error)
	//DeriveSymmetricKey(protocol Protocol, keyID string, counterparty Counterparty) (*ec.SymmetricKey, error)
	//RevealSpecificSecret(counterparty Counterparty, protocol Protocol, keyID string) ([]byte, error)
}
