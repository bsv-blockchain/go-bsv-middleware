package wallet_test

import (
	"context"
	"testing"

	"github.com/4chain-ag/go-bsv-middlewares/pkg/temporary/wallet"
	"github.com/stretchr/testify/require"
)

// Test GetPublicKey for valid cases
func TestMockWallet_GetPublicKey_HappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := wallet.NewMockWallet(wallet.WithKeyDeriver)

	// when
	identityKey, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{IdentityKey: true})

	// then
	require.NoError(t, err)
	require.Equal(t, wallet.IdentityKeyMock, identityKey)

	// when
	derivedKey, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{
		IdentityKey: false,
		ProtocolID:  "auth-protocol",
		KeyID:       "key123",
	})

	// then
	require.NoError(t, err)
	require.Equal(t, wallet.DerivedKeyMock, derivedKey)
}

// Test GetPublicKey for invalid cases
func TestMockWallet_GetPublicKey_UnhappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := wallet.NewMockWallet(wallet.WithKeyDeriver)

	// when
	_, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{Privileged: true})

	// then
	require.Error(t, err)
	require.Equal(t, wallet.ErrorNoPrivilege, err.Error())

	// when
	_, err = w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{
		IdentityKey: false,
		KeyID:       "key123",
	})

	// then
	require.Error(t, err)
	require.Equal(t, wallet.ErrorMissingParams, err.Error())

	// given
	wNoDeriver := wallet.NewMockWallet(wallet.WithoutKeyDeriver)

	// when
	_, err = wNoDeriver.GetPublicKey(ctx, wallet.GetPublicKeyOptions{IdentityKey: true})

	// then
	require.Error(t, err)
	require.Equal(t, wallet.ErrorKeyDeriver, err.Error())
}

// Test CreateSignature and VerifySignature
func TestMockWallet_CreateAndVerifySignature_HappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := wallet.NewMockWallet(wallet.WithKeyDeriver)

	data := []byte("test-data")
	protocolID := "auth-protocol"
	keyID := "key123"
	counterparty := "peer"

	// when
	signature, err := w.CreateSignature(ctx, data, protocolID, keyID, counterparty)

	// then
	require.NoError(t, err)
	require.Equal(t, []byte(wallet.MockSignature), signature)

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
	w := wallet.NewMockWallet(wallet.WithKeyDeriver)

	// when
	nonce, err := w.CreateNonce(ctx)

	// then
	require.NoError(t, err)
	require.Equal(t, wallet.MockNonce, nonce)

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
	w := wallet.NewMockWallet(wallet.WithKeyDeriver)

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
