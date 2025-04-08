package payment_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/payment"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	fixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addIdentityToContext(r *http.Request, identityKey string) *http.Request {
	ctx := context.WithValue(r.Context(), transport.IdentityKey, identityKey)
	return r.WithContext(ctx)
}

func mockWalletSetup(t *testing.T, w wallet.WalletInterface, expectedNonce string) {
	nonce, err := w.CreateNonce(context.Background())
	require.NoError(t, err)

	valid, err := w.VerifyNonce(context.Background(), nonce)
	require.NoError(t, err)
	require.True(t, valid, "CreateNonce should create a valid nonce")

	valid, err = w.VerifyNonce(context.Background(), expectedNonce)
	require.NoError(t, err)
	require.True(t, valid, "Mock wallet should recognize MockNonce as valid")
}

func TestNewMiddleware(t *testing.T) {
	t.Run("Returns error with no wallet", func(t *testing.T) {
		options := payment.Options{}

		_, err := payment.New(options)

		assert.ErrorIs(t, err, payment.ErrNoWallet)
		assert.Equal(t, payment.ErrNoWallet, err)
	})

	t.Run("Creates middleware with valid options", func(t *testing.T) {
		key, err := ec.NewPrivateKey()
		if err != nil {
			require.NoError(t, err)
		}

		mockWallet := wallet.NewMockPaymentWallet(key)
		options := payment.Options{
			Wallet: mockWallet,
		}

		middleware, err := payment.New(options)

		assert.NoError(t, err)
		assert.NotNil(t, middleware)
	})
}

func TestMiddleware_Handler_MissingAuthContext(t *testing.T) {
	key, err := ec.NewPrivateKey()
	if err != nil {
		require.NoError(t, err)
	}
	mockWallet := wallet.NewMockPaymentWallet(key)
	middleware, err := payment.New(payment.Options{
		Wallet: mockWallet,
	})
	require.NoError(t, err)

	var handlerCalled bool
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]any
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, payment.ErrCodeServerMisconfigured, resp["code"])
}

func TestMiddleware_Handler_FreeAccess(t *testing.T) {
	key, err := ec.NewPrivateKey()
	if err != nil {
		require.NoError(t, err)
	}
	mockWallet := wallet.NewMockPaymentWallet(key)
	middleware, err := payment.New(payment.Options{
		Wallet: mockWallet,
		CalculateRequestPrice: func(r *http.Request) (int, error) {
			return 0, nil
		},
	})
	require.NoError(t, err)

	var handlerCalled bool
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		info, ok := payment.GetPaymentInfoFromContext(r.Context())
		assert.True(t, ok)
		assert.NotNil(t, info)
		assert.Equal(t, 0, info.SatoshisPaid)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req = addIdentityToContext(req, "test-identity-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
}

func TestMiddleware_Handler_PaymentRequired(t *testing.T) {
	key, err := ec.NewPrivateKey()
	if err != nil {
		require.NoError(t, err)
	}
	mockWallet := wallet.NewMockPaymentWallet(key)
	middleware, err := payment.New(payment.Options{
		Wallet: mockWallet,
		CalculateRequestPrice: func(r *http.Request) (int, error) {
			return 100, nil
		},
	})
	require.NoError(t, err)

	var handlerCalled bool
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req = addIdentityToContext(req, "test-identity-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusPaymentRequired, w.Code)

	var terms payment.PaymentTerms
	err = json.NewDecoder(w.Body).Decode(&terms)
	require.NoError(t, err)

	assert.Equal(t, payment.NetworkBSV, terms.Network)
	assert.Equal(t, payment.PaymentVersion, terms.Version)
	assert.Equal(t, 100, terms.SatoshisRequired)
	assert.NotEmpty(t, terms.DerivationPrefix)
}

func TestMiddleware_Handler_InvalidPaymentData(t *testing.T) {
	key, err := ec.NewPrivateKey()
	if err != nil {
		require.NoError(t, err)
	}
	mockWallet := wallet.NewMockPaymentWallet(key)
	middleware, err := payment.New(payment.Options{
		Wallet: mockWallet,
	})
	require.NoError(t, err)

	var handlerCalled bool
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req = addIdentityToContext(req, "test-identity-key")
	req.Header.Set(payment.HeaderPayment, "invalid-json-data")

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, payment.ErrCodeMalformedPayment, resp["code"])
}

func TestMiddleware_Handler_ProcessPayment(t *testing.T) {
	t.Run("successful payment", func(t *testing.T) {
		key, err := ec.NewPrivateKey()
		if err != nil {
			require.NoError(t, err)
		}
		mockWallet := wallet.NewMockPaymentWallet(key)
		mockWalletSetup(t, mockWallet, fixtures.MockNonce)

		mockWallet.SetInternalizeActionResult(wallet.InternalizeActionResult{
			Accepted: true,
		})

		middleware, err := payment.New(payment.Options{
			Wallet: mockWallet,
			CalculateRequestPrice: func(r *http.Request) (int, error) {
				return 100, nil
			},
		})
		require.NoError(t, err)

		var handlerCalled bool
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			info, ok := payment.GetPaymentInfoFromContext(r.Context())
			assert.True(t, ok)
			assert.NotNil(t, info)
			assert.Equal(t, 100, info.SatoshisPaid)
			assert.True(t, info.Accepted)
		}))

		paymentData := payment.Payment{
			ModeID:           "bsv-direct",
			DerivationPrefix: fixtures.MockNonce,
			DerivationSuffix: "test-suffix",
			Transaction:      []byte{1, 2, 3, 4},
		}
		paymentJSON, err := json.Marshal(paymentData)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req = addIdentityToContext(req, "test-identity-key")
		req.Header.Set(payment.HeaderPayment, string(paymentJSON))

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "100", w.Header().Get(payment.HeaderSatoshisPaid))

		assert.True(t, mockWallet.InternalizeActionCalled)
		require.NotEmpty(t, mockWallet.InternalizeActionArgs.Outputs)
		require.NotNil(t, mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance)
		assert.Equal(t, fixtures.MockNonce, mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.DerivationPrefix)
		assert.Equal(t, "test-suffix", mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.DerivationSuffix)
		assert.Equal(t, "test-identity-key", mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.SenderIdentityKey)
	})

	t.Run("wallet returns error", func(t *testing.T) {
		expectedError := errors.New("payment validation failed")
		key, err := ec.NewPrivateKey()
		if err != nil {
			require.NoError(t, err)
		}
		mockWallet := wallet.NewMockPaymentWallet(key)
		mockWalletSetup(t, mockWallet, fixtures.MockNonce)
		mockWallet.SetInternalizeActionError(expectedError)

		middleware, err := payment.New(payment.Options{
			Wallet: mockWallet,
		})
		require.NoError(t, err)

		var handlerCalled bool
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		}))

		paymentData := payment.Payment{
			ModeID:           "bsv-direct",
			DerivationPrefix: fixtures.MockNonce,
			DerivationSuffix: "test-suffix",
			Transaction:      []byte{1, 2, 3, 4},
		}
		paymentJSON, err := json.Marshal(paymentData)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req = addIdentityToContext(req, "test-identity-key")
		req.Header.Set(payment.HeaderPayment, string(paymentJSON))

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp map[string]any
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		assert.Equal(t, payment.ErrCodePaymentFailed, resp["code"])
		assert.Contains(t, resp["description"].(string), expectedError.Error())
	})
}
