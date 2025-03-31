package payment

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	fixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addIdentityToContext adds identity to request context
func addIdentityToContext(r *http.Request, identityKey string) *http.Request {
	ctx := context.WithValue(r.Context(), transport.IdentityKey, identityKey)
	return r.WithContext(ctx)
}

func TestNewMiddleware(t *testing.T) {
	t.Run("Returns error with no wallet", func(t *testing.T) {
		_, err := New(Options{})

		assert.Error(t, err)
		assert.Equal(t, ErrNoWallet, err)
	})

	t.Run("Creates middleware with valid options", func(t *testing.T) {
		mockWallet := wallet.NewMockPaymentWallet()
		middleware, err := New(Options{
			Wallet: mockWallet,
		})

		assert.NoError(t, err)
		assert.NotNil(t, middleware)
	})
}

func TestFreeAccessFlow(t *testing.T) {
	t.Run("Requires auth middleware", func(t *testing.T) {
		mockWallet := wallet.NewMockPaymentWallet()
		middleware, err := New(Options{
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
	})

	t.Run("Free requests pass through with payment info", func(t *testing.T) {
		mockWallet := wallet.NewMockPaymentWallet()
		middleware, err := New(Options{
			Wallet: mockWallet,
			CalculateRequestPrice: func(r *http.Request) (int, error) {
				return 0, nil
			},
		})
		require.NoError(t, err)

		var handlerCalled bool
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			info, ok := GetPaymentInfoFromContext(r.Context())
			assert.True(t, ok)
			assert.NotNil(t, info)
			assert.Equal(t, 0, info.SatoshisPaid)
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req = addIdentityToContext(req, "test-identity-key")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
	})
}

func TestPaymentRequiredFlow(t *testing.T) {
	t.Run("Returns 402 Payment Required with headers", func(t *testing.T) {
		mockWallet := wallet.NewMockPaymentWallet()
		middleware, err := New(Options{
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
		req = addIdentityToContext(req, "test-identity-key") // Add identity to context
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusPaymentRequired, w.Code)

		assert.Equal(t, PaymentVersion, w.Header().Get("X-BSV-Payment-Version"))
		assert.Equal(t, "100", w.Header().Get("X-BSV-Payment-Satoshis-Required"))
		assert.NotEmpty(t, w.Header().Get("X-BSV-Payment-Derivation-Prefix"))

		var resp map[string]any
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		assert.Equal(t, "error", resp["status"])
		assert.Equal(t, ErrCodePaymentRequired, resp["code"])
		assert.Contains(t, resp["description"].(string), "BSV payment is required")
		assert.Equal(t, float64(100), resp["satoshisRequired"])
	})
}

func TestPaymentValidation(t *testing.T) {
	t.Run("Rejects malformed payment header", func(t *testing.T) {
		mockWallet := wallet.NewMockPaymentWallet()
		middleware, err := New(Options{
			Wallet: mockWallet,
		})
		require.NoError(t, err)

		var handlerCalled bool
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req = addIdentityToContext(req, "test-identity-key")
		req.Header.Set("X-BSV-Payment", "invalid-json")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp map[string]any
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		assert.Equal(t, ErrCodeMalformedPayment, resp["code"])
	})

	t.Run("Handles payment validation error", func(t *testing.T) {
		mockWallet := wallet.NewMockPaymentWallet()
		mockWallet.SetInternalizeActionError(errors.New("payment validation failed"))

		middleware, err := New(Options{
			Wallet: mockWallet,
		})
		require.NoError(t, err)

		var handlerCalled bool
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		}))

		derivationPrefix := fixtures.MockNonce

		paymentData := Payment{
			DerivationPrefix: derivationPrefix,
			DerivationSuffix: "test-suffix",
			Transaction:      []byte{1, 2, 3},
		}
		paymentJSON, _ := json.Marshal(paymentData)

		req := httptest.NewRequest("GET", "/", nil)
		req = addIdentityToContext(req, "test-identity-key")
		req.Header.Set("X-BSV-Payment", string(paymentJSON))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp map[string]any
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		assert.Equal(t, ErrCodePaymentFailed, resp["code"])
		assert.Contains(t, resp["description"].(string), "payment validation failed")
	})

	t.Run("Processes valid payment", func(t *testing.T) {
		mockWallet := wallet.NewMockPaymentWallet()
		middleware, err := New(Options{
			Wallet: mockWallet,
			CalculateRequestPrice: func(r *http.Request) (int, error) {
				return 100, nil
			},
		})
		require.NoError(t, err)

		var handlerCalled bool
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			info, ok := GetPaymentInfoFromContext(r.Context())
			assert.True(t, ok)
			assert.NotNil(t, info)
			assert.Equal(t, 100, info.SatoshisPaid)
			assert.True(t, info.Accepted)
		}))

		derivationPrefix := fixtures.MockNonce

		paymentData := Payment{
			DerivationPrefix: derivationPrefix,
			DerivationSuffix: "test-suffix",
			Transaction:      []byte{1, 2, 3},
		}
		paymentJSON, _ := json.Marshal(paymentData)

		req := httptest.NewRequest("GET", "/", nil)
		req = addIdentityToContext(req, "test-identity-key")
		req.Header.Set("X-BSV-Payment", string(paymentJSON))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "100", w.Header().Get("X-BSV-Payment-Satoshis-Paid"))

		assert.True(t, mockWallet.InternalizeActionCalled)
		assert.Equal(t, 0, mockWallet.InternalizeActionArgs.Outputs[0].OutputIndex)
		assert.Equal(t, "wallet payment", mockWallet.InternalizeActionArgs.Outputs[0].Protocol)
		assert.Equal(t, derivationPrefix, mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.DerivationPrefix)
		assert.Equal(t, "test-suffix", mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.DerivationSuffix)
		assert.Equal(t, "test-identity-key", mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.SenderIdentityKey)
	})
}
