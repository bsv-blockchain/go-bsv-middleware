package wallet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	wallet "github.com/bsv-blockchain/go-bsv-middleware/pkg/temporary/wallet/test"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Wallet provides a simple mock implementation of WalletInterface.
type Wallet struct {
	keyDeriver  *KeyDeriver
	validNonces map[string]bool
	nonces      []string
}

// NewMockWallet creates a new mock wallet with given privateKey and nonces if provided.
func NewMockWallet(privateKey *ec.PrivateKey, nonces ...string) WalletInterface {
	return &Wallet{
		validNonces: make(map[string]bool),
		nonces:      append([]string(nil), nonces...),
		keyDeriver:  NewKeyDeriver(privateKey),
	}
}

// GetPublicKey retrieves the public key based on the provided arguments.
func (m *Wallet) GetPublicKey(args *GetPublicKeyArgs, _ string) (*GetPublicKeyResult, error) {
	if args == nil {
		return nil, errors.New("args must be provided")
	}
	if args.IdentityKey {
		return &GetPublicKeyResult{
			PublicKey: m.keyDeriver.rootKey.PubKey(),
		}, nil
	}

	if args.ProtocolID.Protocol == "" || args.KeyID == "" {
		return nil, errors.New("protocolID and keyID are required if identityKey is false or undefined")
	}

	// Handle default counterparty (self)
	counterparty := args.Counterparty
	if counterparty.Type == CounterpartyUninitialized {
		counterparty = Counterparty{
			Type: CounterpartyTypeSelf,
		}
	}

	pubKey, err := m.keyDeriver.DerivePublicKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
		args.ForSelf,
	)
	if err != nil {
		return nil, err
	}

	return &GetPublicKeyResult{
		PublicKey: pubKey,
	}, nil
}

// CreateSignature creates a digital signature for the given arguments
func (w *Wallet) CreateSignature(args *CreateSignatureArgs, _ string) (*CreateSignatureResult, error) {
	if args == nil {
		return nil, errors.New("args must be provided")
	}
	if len(args.Data) == 0 && len(args.DashToDirectlySign) == 0 {
		return nil, errors.New("args.data or args.hashToDirectlySign must be valid")
	}

	var hash []byte
	if len(args.DashToDirectlySign) > 0 {
		hash = args.DashToDirectlySign
	} else {
		sum := sha256.Sum256(args.Data)
		hash = sum[:]
	}

	counterparty := args.Counterparty
	if counterparty.Type == CounterpartyUninitialized {
		counterparty = Counterparty{
			Type: CounterpartyTypeAnyone,
		}
	}

	privKey, err := w.keyDeriver.DerivePrivateKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %w", err)
	}

	signature, err := privKey.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	return &CreateSignatureResult{
		Signature: *signature,
	}, nil
}

// VerifySignature checks the validity of a cryptographic signature.
// It verifies that the signature was created using the expected protocol and key ID.
func (w *Wallet) VerifySignature(args *VerifySignatureArgs) (*VerifySignatureResult, error) {
	if args == nil {
		return nil, errors.New("args must be provided")
	}
	if len(args.Data) == 0 && len(args.HashToDirectlyVerify) == 0 {
		return nil, errors.New("args.data or args.hashToDirectlyVerify must be valid")
	}

	var hash []byte
	if len(args.HashToDirectlyVerify) > 0 {
		hash = args.HashToDirectlyVerify
	} else {
		sum := sha256.Sum256(args.Data)
		hash = sum[:]
	}

	counterparty := args.Counterparty
	if counterparty.Type == CounterpartyUninitialized {
		counterparty = Counterparty{
			Type: CounterpartyTypeSelf,
		}
	}

	pubKey, err := w.keyDeriver.DerivePublicKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
		args.ForSelf,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	valid := args.Signature.Verify(hash, pubKey)
	if !valid {
		return nil, errors.New("signature is not valid")
	}

	return &VerifySignatureResult{
		Valid: valid,
	}, nil
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
