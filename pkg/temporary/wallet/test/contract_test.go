package wallet_test

import (
	"context"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	fixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/stretchr/testify/require"
)

// Test GetPublicKey for valid cases
func TestMockWallet_GetPublicKey_HappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := wallet.NewMockWallet(fixtures.WithKeyDeriver, nil)

	// when
	identityKey, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{IdentityKey: true})

	// then
	require.NoError(t, err)
	require.Equal(t, fixtures.ServerIdentityKey, identityKey)

	// when
	derivedKey, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{
		IdentityKey: false,
		ProtocolID:  "auth-protocol",
		KeyID:       "key123",
	})

	// then
	require.NoError(t, err)
	require.Equal(t, fixtures.DerivedKeyMock, derivedKey)
}

// Test GetPublicKey for invalid cases
func TestMockWallet_GetPublicKey_UnhappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := wallet.NewMockWallet(fixtures.WithKeyDeriver, nil)

	// when
	_, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{Privileged: true})

	// then
	require.Error(t, err)
	require.Equal(t, fixtures.ErrorNoPrivilege, err.Error())

	// when
	_, err = w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{
		IdentityKey: false,
		KeyID:       "key123",
	})

	// then
	require.Error(t, err)
	require.Equal(t, fixtures.ErrorMissingParams, err.Error())

	// given
	wNoDeriver := wallet.NewMockWallet(fixtures.WithoutKeyDeriver, nil)

	// when
	_, err = wNoDeriver.GetPublicKey(ctx, wallet.GetPublicKeyOptions{IdentityKey: true})

	// then
	require.Error(t, err)
	require.Equal(t, fixtures.ErrorKeyDeriver, err.Error())
}

// Test CreateSignature and VerifySignature
func TestMockWallet_CreateAndVerifySignature_HappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := wallet.NewMockWallet(fixtures.WithKeyDeriver, nil)

	data := []byte("test-data")
	protocolID := "auth-protocol"
	keyID := "key123"
	counterparty := "peer"

	// when
	signature, err := w.CreateSignature(ctx, data, protocolID, keyID, counterparty)

	// then
	require.NoError(t, err)
	require.Equal(t, []byte(fixtures.MockSignature), signature)

	// when
	isValid, err := w.VerifySignature(ctx, data, signature, protocolID, keyID, counterparty)

	// then
	require.NoError(t, err)
	require.True(t, isValid)
}

// Test CreateNonce and VerifyNonce
func TestMockWallet_CreateAndVerifyNonce_HappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := wallet.NewMockWallet(fixtures.WithKeyDeriver, nil)

	// when
	nonce, err := w.CreateNonce(ctx)

	// then
	require.NoError(t, err)
	require.Equal(t, fixtures.MockNonce, nonce)

	// when
	isValid, err := w.VerifyNonce(ctx, nonce)

	// then
	require.NoError(t, err)
	require.True(t, isValid)
}

// Test VerifySignature for invalid cases
func TestMockWallet_VerifySignature_UnhappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := wallet.NewMockWallet(fixtures.WithKeyDeriver, nil)

	data := []byte("test-data")
	protocolID := "auth-protocol"
	keyID := "key123"
	counterparty := "peer"

	// when
	isValid, err := w.VerifySignature(ctx, data, []byte("invalid-signature"), protocolID, keyID, counterparty)

	// then
	require.NoError(t, err)
	require.False(t, isValid)
}
