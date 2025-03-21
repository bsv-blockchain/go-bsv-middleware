package wallet_test

import (
	"context"
	"testing"

	"github.com/4chain-ag/go-bsv-middlewares/pkg/wallet"
	mock "github.com/4chain-ag/go-bsv-middlewares/testutil/mock/wallet"
	"github.com/stretchr/testify/require"
)

// Test GetPublicKey for valid cases
func TestMockWallet_GetPublicKey_HappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := mock.NewMockWallet(mock.WithKeyDeriver)

	// when
	identityKey, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{IdentityKey: true})

	// then
	require.NoError(t, err)
	require.Equal(t, mock.IdentityKeyMock, identityKey)

	// when
	derivedKey, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{
		IdentityKey: false,
		ProtocolID:  "auth-protocol",
		KeyID:       "key123",
	})

	// then
	require.NoError(t, err)
	require.Equal(t, mock.DerivedKeyMock, derivedKey)
}

// Test GetPublicKey for invalid cases
func TestMockWallet_GetPublicKey_UnhappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := mock.NewMockWallet(mock.WithKeyDeriver)

	// when
	_, err := w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{Privileged: true})

	// then
	require.Error(t, err)
	require.Equal(t, mock.ErrorNoPrivilege, err.Error())

	// when
	_, err = w.GetPublicKey(ctx, wallet.GetPublicKeyOptions{
		IdentityKey: false,
		KeyID:       "key123",
	})

	// then
	require.Error(t, err)
	require.Equal(t, mock.ErrorMissingParams, err.Error())

	// given
	wNoDeriver := mock.NewMockWallet(mock.WithoutKeyDeriver)

	// when
	_, err = wNoDeriver.GetPublicKey(ctx, wallet.GetPublicKeyOptions{IdentityKey: true})

	// then
	require.Error(t, err)
	require.Equal(t, mock.ErrorKeyDeriver, err.Error())
}

// Test CreateSignature and VerifySignature
func TestMockWallet_CreateAndVerifySignature_HappyPath(t *testing.T) {
	// given
	ctx := context.Background()
	w := mock.NewMockWallet(mock.WithKeyDeriver)

	data := []byte("test-data")
	protocolID := "auth-protocol"
	keyID := "key123"
	counterparty := "peer"

	// when
	signature, err := w.CreateSignature(ctx, data, protocolID, keyID, counterparty)

	// then
	require.NoError(t, err)
	require.Equal(t, []byte(mock.MockSignature), signature)

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
	w := mock.NewMockWallet(mock.WithKeyDeriver)

	// when
	nonce, err := w.CreateNonce(ctx)

	// then
	require.NoError(t, err)
	require.Equal(t, mock.MockNonce, nonce)

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
	w := mock.NewMockWallet(mock.WithKeyDeriver)

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
