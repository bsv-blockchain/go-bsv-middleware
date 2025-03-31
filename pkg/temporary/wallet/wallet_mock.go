package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
)

// Wallet provides a simple mock implementation of WalletInterface.
type Wallet struct {
	identityKey string
	keyDeriver  bool
	validNonces map[string]bool
	nonces      []string
}

// NewMockWallet creates a new mock wallet with the following options:
// - keyDeriver: Enables or disables key derivation.
// - identityKey: Uses the provided identity key or a basic one if none is given.
// - nonces: Uses the provided nonces or basic one if none are provided.
func NewMockWallet(enableKeyDeriver bool, identityKey *string, nonces ...string) WalletInterface {
	if identityKey == nil {
		identityKey = &wallet.ServerIdentityKey
	}
	return &Wallet{
		identityKey: *identityKey,
		keyDeriver:  enableKeyDeriver,
		validNonces: make(map[string]bool),
		nonces:      append([]string(nil), nonces...),
	}
}

// GetPublicKey returns a mock public key while validating required parameters.
func (m *Wallet) GetPublicKey(ctx context.Context, options GetPublicKeyOptions) (string, error) {
	if ctx.Err() != nil {
		return "", fmt.Errorf("ctx err: %w", ctx.Err())
	}

	if options.Privileged {
		return "", errors.New(wallet.ErrorNoPrivilege)
	}

	if options.IdentityKey {
		if !m.keyDeriver {
			return "", errors.New(wallet.ErrorKeyDeriver)
		}
		return m.identityKey, nil
	}

	if options.ProtocolID == nil || options.KeyID == "" || options.KeyID == " " {
		return "", errors.New(wallet.ErrorMissingParams)
	}

	if !m.keyDeriver {
		return "", errors.New(wallet.ErrorKeyDeriver)
	}

	return wallet.DerivedKeyMock, nil
}

// CreateSignature returns a mock signature.
func (m *Wallet) CreateSignature(ctx context.Context, data []byte, protocolID any, keyID string, counterparty string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("ctx err: %w", ctx.Err())
	}

	if len(data) == 0 || keyID == "" || counterparty == "" {
		return nil, errors.New(wallet.ErrorInvalidInput)
	}

	return []byte(wallet.MockSignature), nil
}

// VerifySignature returns true if the signature matches expected mock data.
func (m *Wallet) VerifySignature(ctx context.Context, data []byte, signature []byte, protocolID any, keyID string, counterparty string) (bool, error) {
	if ctx.Err() != nil {
		return false, fmt.Errorf("ctx err: %w", ctx.Err())
	}

	return string(signature) == wallet.MockSignature, nil
}

// CreateNonce generates a deterministic nonce.
func (m *Wallet) CreateNonce(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", fmt.Errorf("ctx err: %w", ctx.Err())
	}

	newNonce := wallet.MockNonce

	if len(m.nonces) != 0 {
		newNonce = m.nonces[0]
		m.nonces = m.nonces[1:]

		if len(m.nonces) == 0 {
			m.nonces = append([]string(nil), wallet.DefaultNonces...)
		}
	}

	m.validNonces[newNonce] = true
	return newNonce, nil
}

// VerifyNonce checks if the nonce exists.
func (m *Wallet) VerifyNonce(ctx context.Context, nonce string) (bool, error) {
	if ctx.Err() != nil {
		return false, fmt.Errorf("ctx err: %w", ctx.Err())
	}

	_, exists := m.validNonces[nonce]
	return exists, nil
}

// ListCertificates returns an empty list.
func (m *Wallet) ListCertificates(ctx context.Context, certifiers []string, types []string) ([]Certificate, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("ctx err: %w", ctx.Err())
	}

	return []Certificate{}, nil
}

// ProveCertificate returns an empty map.
func (m *Wallet) ProveCertificate(ctx context.Context, certificate Certificate, verifier string, fieldsToReveal []string) (map[string]string, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("ctx err: %w", ctx.Err())
	}

	return map[string]string{}, nil
}
