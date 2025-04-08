package wallet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockPaymentWallet(t *testing.T) {
	key, err := ec.NewPrivateKey()
	if err != nil {
		require.NoError(t, err)
	}

	t.Run("Implements PaymentInterface", func(t *testing.T) {
		var _ wallet.PaymentInterface = &wallet.MockPaymentWallet{}
	})

	t.Run("Records InternalizeAction arguments", func(t *testing.T) {
		mock := wallet.NewMockPaymentWallet(key)
		args := wallet.InternalizeActionArgs{
			Tx: []byte{1, 2, 3},
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    "wallet payment",
					PaymentRemittance: &wallet.PaymentRemittance{
						DerivationPrefix:  "prefix",
						DerivationSuffix:  "suffix",
						SenderIdentityKey: "sender",
					},
				},
			},
			Description: "Test payment",
		}

		result, err := mock.InternalizeAction(context.Background(), args)

		assert.NoError(t, err)
		assert.True(t, result.Accepted)
		assert.True(t, mock.InternalizeActionCalled)
		assert.Equal(t, args, mock.InternalizeActionArgs)
	})

	t.Run("Returns configured error", func(t *testing.T) {
		mock := wallet.NewMockPaymentWallet(key)
		expectedErr := errors.New("payment error")
		mock.SetInternalizeActionError(expectedErr)

		_, err := mock.InternalizeAction(context.Background(), wallet.InternalizeActionArgs{})

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Returns configured result", func(t *testing.T) {
		mock := wallet.NewMockPaymentWallet(key)
		expectedResult := wallet.InternalizeActionResult{Accepted: false}
		mock.SetInternalizeActionResult(expectedResult)

		result, err := mock.InternalizeAction(context.Background(), wallet.InternalizeActionArgs{})

		assert.NoError(t, err)
		assert.Equal(t, expectedResult, result)
	})
}
