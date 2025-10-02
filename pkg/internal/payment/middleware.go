package payment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/authctx"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/payctx"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/slogx"
	"github.com/go-softwarelab/common/pkg/to"
)

type Config struct {
	Logger *slog.Logger

	// CalculateRequestPrice determines the cost in satoshis for a request
	CalculateRequestPrice func(r *http.Request) (int, error)
}

// Middleware is the payment middleware handler that implements Direct Payment Protocol (DPP) for HTTP-based micropayments
type Middleware struct {
	log                   *slog.Logger
	wallet                wallet.Interface
	calculateRequestPrice func(r *http.Request) (int, error)
	nextHandler           http.Handler
}

func NewMiddleware(next http.Handler, wallet wallet.Interface, opts ...func(*Config)) *Middleware {
	cfg := to.OptionsWithDefault(Config{
		CalculateRequestPrice: DefaultPriceFunc,
		Logger:                slog.Default(),
	}, opts...)

	logger := slogx.Child(cfg.Logger, "PaymentMiddleware")

	return &Middleware{
		wallet:                wallet,
		nextHandler:           next,
		log:                   logger,
		calculateRequestPrice: cfg.CalculateRequestPrice,
	}
}

// Handler returns a middleware handler function that processes payments
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	identityKey, err := authctx.ShouldGetIdentity(r.Context())
	if err != nil {
		m.log.ErrorContext(ctx, "Failed to get identity from request context", slogx.Error(err))
		m.respondWith(w, ErrServerMisconfigured)
		return
	}

	log := m.log.With(slog.String("identityKey", identityKey.ToDERHex()))

	price, err := m.calculateRequestPrice(r)
	if err != nil {
		log.ErrorContext(ctx, "Failed to calculate request price", slogx.Error(err))
		m.respondWith(w, ErrPaymentInternal)
		return
	}

	if price == 0 {
		log.DebugContext(ctx, "Request without payment requested, proceeding to next handler", slog.Int("price", price))
		m.proceedWithoutPayment(w, r)
		return
	}

	paymentData, err := m.extractPaymentData(r)
	if err != nil {
		log.ErrorContext(ctx, "Failed to extract payment data", slogx.Error(err))
		m.respondWith(w, ErrMalformedPayment)
		return
	}

	if paymentData == nil {
		log.DebugContext(ctx, "Requesting payment", slog.Int("price", price))
		err = m.requestPayment(w, r, price)
		if err != nil {
			log.ErrorContext(ctx, "Failed to prepare payment request", slogx.Error(err))
			m.respondWith(w, ErrPaymentInternal)
		}
		return
	}

	log.DebugContext(ctx, "Processing payment", slog.Int("price", price))
	paymentInfo, processErr := m.processPayment(ctx, paymentData, identityKey, price)
	if processErr != nil {
		log.ErrorContext(ctx, "Failed to process payment", slogx.Error(processErr.Cause))
		m.respondWith(w, processErr)
		return
	}

	log.DebugContext(ctx, "Request successfully paid, proceeding to next handler", slog.Int("price", price))
	m.proceedWithSuccessfulPayment(w, r, paymentInfo)
}

func (m *Middleware) respondWith(w http.ResponseWriter, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.GetStatusCode())
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		m.log.Error("Error writing response body", slog.Any("response", resp), slogx.Error(err))
		return
	}
}

func (m *Middleware) proceedWithoutPayment(w http.ResponseWriter, r *http.Request) {
	ctx := payctx.WithoutPayment(r.Context())
	m.nextHandler.ServeHTTP(w, r.WithContext(ctx))
}

func (m *Middleware) extractPaymentData(r *http.Request) (*Payment, error) {
	paymentHeader := r.Header.Get(HeaderPayment)
	if paymentHeader == "" {
		return nil, nil
	}

	var payment Payment
	if err := json.Unmarshal([]byte(paymentHeader), &payment); err != nil {
		return nil, fmt.Errorf("invalid payment data format: %w", err)
	}

	return &payment, nil
}

func (m *Middleware) requestPayment(w http.ResponseWriter, r *http.Request, price int) error {
	derivationPrefix, err := sdkUtils.CreateNonce(r.Context(), m.wallet, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		return fmt.Errorf("failed to prepare derivation prefix as nonce: %w", err)
	}

	w.Header().Set(HeaderVersion, PaymentVersion)
	w.Header().Set(HeaderSatoshisRequired, strconv.Itoa(price))
	w.Header().Set(HeaderDerivationPrefix, derivationPrefix)

	m.respondWith(w, ErrPaymentRequired.WithSatoshisRequired(price))

	return nil
}

func (m *Middleware) proceedWithSuccessfulPayment(w http.ResponseWriter, r *http.Request, paymentInfo *payctx.Payment) {
	ctx := payctx.WithPayment(r.Context(), paymentInfo)
	w.Header().Set(HeaderSatoshisPaid, strconv.Itoa(paymentInfo.SatoshisPaid))
	m.nextHandler.ServeHTTP(w, r.WithContext(ctx))
}

func (m *Middleware) processPayment(
	ctx context.Context,
	paymentData *Payment,
	identityKey *ec.PublicKey,
	price int,
) (*payctx.Payment, *ProcessingError) {
	derivationPrefix, err := base64.StdEncoding.DecodeString(paymentData.DerivationPrefix)
	if err != nil {
		return nil, NewProcessingError(ErrInvalidDerivationPrefix, fmt.Errorf("invalid derivation prefix: must be base64: %w", err))
	}

	valid, err := sdkUtils.VerifyNonce(ctx, paymentData.DerivationPrefix, m.wallet, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		return nil, NewProcessingError(ErrInvalidDerivationPrefix, fmt.Errorf("error verifying derivation prefix as nonce: %w", err))
	}
	if !valid {
		return nil, NewProcessingError(ErrInvalidDerivationPrefix, fmt.Errorf("derivation prefix is invalid nonce"))
	}

	derivationSuffix, err := base64.StdEncoding.DecodeString(paymentData.DerivationSuffix)
	if err != nil {
		return nil, NewProcessingError(ErrInvalidDerivationSuffix, fmt.Errorf("invalid derivation suffix: must be base64: %w", err))
	}

	result, err := m.wallet.InternalizeAction(ctx, wallet.InternalizeActionArgs{
		Tx: paymentData.Transaction,
		Outputs: []wallet.InternalizeOutput{
			{
				OutputIndex: 0,
				Protocol:    wallet.InternalizeProtocolWalletPayment,
				PaymentRemittance: &wallet.Payment{
					DerivationPrefix:  derivationPrefix,
					DerivationSuffix:  derivationSuffix,
					SenderIdentityKey: identityKey,
				},
			},
		},
		Description: "Payment for request",
	},
		PaymentOriginator,
	)
	if err != nil {
		return nil, NewProcessingError(ErrPaymentFailed, fmt.Errorf("payment processing failed: %w", err))
	}

	return &payctx.Payment{
		SatoshisPaid: price,
		Accepted:     result.Accepted,
		Tx:           paymentData.Transaction,
	}, nil
}
