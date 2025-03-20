package mock

import (
	"context"
	"errors"
	"github.com/4chain-ag/go-bsv-middlewares/pkg/wallet"
)

// MockWallet provides a simple mock implementation of WalletInterface.
type MockWallet struct {
	identityKey string
	keyDeriver  bool // Simulates whether keyDeriver is initialized
	validNonces map[string]bool
}

// NewMockWallet creates a new mock wallet with predefined keys.
func NewMockWallet(keyDeriver bool) wallet.WalletInterface {
	return &MockWallet{
		identityKey: "02mockidentitykey0000000000000000000000000000000000000000000000000000000",
		keyDeriver:  keyDeriver,
		validNonces: make(map[string]bool),
	}
}

// GetPublicKey returns a mock public key while validating required parameters.
func (m *MockWallet) GetPublicKey(ctx context.Context, options wallet.GetPublicKeyOptions) (string, error) {
	// given
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	// when
	if options.Privileged {
		return "", errors.New("no privilege support")
	}

	if options.IdentityKey {
		if !m.keyDeriver {
			return "", errors.New("keyDeriver is not initialized")
		}
		return m.identityKey, nil
	}

	if options.ProtocolID == nil || options.KeyID == "" || options.KeyID == " " {
		return "", errors.New("protocolID and keyID are required if identityKey is false or undefined")
	}

	if !m.keyDeriver {
		return "", errors.New("keyDeriver is not initialized")
	}

	// then
	return "02mockderivedkey0000000000000000000000000000000000000000000000000000000", nil
}

// CreateSignature returns a mock signature.
func (m *MockWallet) CreateSignature(ctx context.Context, data []byte, protocolID interface{}, keyID string, counterparty string) ([]byte, error) {
	// given
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if len(data) == 0 || keyID == "" || counterparty == "" {
		return nil, errors.New("invalid input")
	}

	// then
	return []byte("mocksignaturedata"), nil
}

// VerifySignature always returns true if the signature matches expected mock data.
func (m *MockWallet) VerifySignature(ctx context.Context, data []byte, signature []byte, protocolID interface{}, keyID string, counterparty string) (bool, error) {
	// given
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// then
	return string(signature) == "mocksignaturedata", nil
}

// CreateNonce generates a deterministic nonce.
func (m *MockWallet) CreateNonce(ctx context.Context) (string, error) {
	// given
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	// when
	nonce := "mocknonce12345"
	m.validNonces[nonce] = true

	// then
	return nonce, nil
}

// VerifyNonce checks if the nonce exists.
func (m *MockWallet) VerifyNonce(ctx context.Context, nonce string) (bool, error) {
	// given
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// when
	_, exists := m.validNonces[nonce]

	// then
	return exists, nil
}

// ListCertificates returns an empty list.
func (m *MockWallet) ListCertificates(ctx context.Context, certifiers []string, types []string) ([]wallet.Certificate, error) {
	// given
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// then
	return []wallet.Certificate{}, nil
}

// ProveCertificate returns an empty map.
func (m *MockWallet) ProveCertificate(ctx context.Context, certificate wallet.Certificate, verifier string, fieldsToReveal []string) (map[string]string, error) {
	// given
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// then
	return map[string]string{}, nil
}
