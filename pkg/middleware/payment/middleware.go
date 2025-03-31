package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
)

// Middleware is the payment middleware handler
type Middleware struct {
	wallet                wallet.PaymentInterface
	calculateRequestPrice func(r *http.Request) (int, error)
}

// New creates a new payment middleware
func New(opts Options) (*Middleware, error) {
	if opts.Wallet == nil {
		return nil, ErrNoWallet
	}

	if opts.CalculateRequestPrice == nil {
		opts.CalculateRequestPrice = DefaultPriceFunc
	}

	return &Middleware{
		wallet:                opts.Wallet,
		calculateRequestPrice: opts.CalculateRequestPrice,
	}, nil
}

// Handler returns a middleware handler function
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityKey, ok := auth.GetIdentityFromContext(r.Context())
		if !ok {
			respondWithError(w, http.StatusInternalServerError, ErrCodeServerMisconfigured,
				ErrAuthMiddlewareMissing.Error())
			return
		}

		price, err := m.calculateRequestPrice(r)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, ErrCodePaymentInternal,
				"Error calculating request price")
			return
		}

		if price == 0 {
			ctx := context.WithValue(r.Context(), PaymentKey, &PaymentInfo{SatoshisPaid: 0})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		paymentHeader := r.Header.Get("X-BSV-Payment")
		if paymentHeader == "" {
			derivationPrefix, err := m.wallet.CreateNonce(r.Context())
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, ErrCodePaymentInternal,
					fmt.Sprintf("Error creating nonce: %s", err.Error()))
				return
			}

			w.Header().Set("X-BSV-Payment-Version", PaymentVersion)
			w.Header().Set("X-BSV-Payment-Satoshis-Required", fmt.Sprintf("%d", price))
			w.Header().Set("X-BSV-Payment-Derivation-Prefix", derivationPrefix)

			respondWithError(w, http.StatusPaymentRequired, ErrCodePaymentRequired,
				"A BSV payment is required to complete this request.",
				map[string]any{"satoshisRequired": price})
			return
		}

		var payment Payment
		if err := json.Unmarshal([]byte(paymentHeader), &payment); err != nil {
			respondWithError(w, http.StatusBadRequest, ErrCodeMalformedPayment,
				"Invalid payment data format")
			return
		}

		valid, err := m.wallet.VerifyNonce(r.Context(), payment.DerivationPrefix)
		if err != nil || !valid {
			respondWithError(w, http.StatusBadRequest, ErrCodeInvalidPrefix,
				"Invalid derivation prefix")
			return
		}

		result, err := m.wallet.InternalizeAction(r.Context(), wallet.InternalizeActionArgs{
			Tx: payment.Transaction,
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    "wallet payment",
					PaymentRemittance: &wallet.PaymentRemittance{
						DerivationPrefix:  payment.DerivationPrefix,
						DerivationSuffix:  payment.DerivationSuffix,
						SenderIdentityKey: identityKey,
					},
				},
			},
			Description: "Payment for request",
		})

		if err != nil {
			respondWithError(w, http.StatusBadRequest, ErrCodePaymentFailed,
				fmt.Sprintf("Payment failed: %s", err.Error()))
			return
		}

		ctx := context.WithValue(r.Context(), PaymentKey, &PaymentInfo{
			SatoshisPaid: price,
			Accepted:     result.Accepted,
			Tx:           payment.Transaction,
		})

		w.Header().Set("X-BSV-Payment-Satoshis-Paid", fmt.Sprintf("%d", price))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// respondWithError creates a standardized error response
func respondWithError(w http.ResponseWriter, status int, code, message string, extraData ...map[string]any) {
	resp := map[string]any{
		"status":      "error",
		"code":        code,
		"description": message,
	}

	if len(extraData) > 0 {
		for k, v := range extraData[0] {
			resp[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		return
	}
}
