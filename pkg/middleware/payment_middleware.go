package middleware

import (
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/payment"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	HeaderPaymentPaid = payment.HeaderSatoshisPaid
)

// PaymentMiddlewareConfig is the configuration for the payment middleware.
type PaymentMiddlewareConfig = payment.Config

// WithPaymentLogger configures the middleware to use the provided logger.
func WithPaymentLogger(logger *slog.Logger) func(*PaymentMiddlewareConfig) {
	// don't override the default
	if logger == nil {
		return func(cfg *PaymentMiddlewareConfig) {}
	}

	return func(cfg *PaymentMiddlewareConfig) {
		cfg.Logger = logger
	}
}

func WithRequestPriceCalculator(calculator func(r *http.Request) (int, error)) func(*PaymentMiddlewareConfig) {
	if calculator == nil {
		panic("calculator must be provided")
	}

	return func(cfg *PaymentMiddlewareConfig) {
		cfg.CalculateRequestPrice = calculator
	}
}

// PaymentMiddlewareFactory is a factory for payment middleware.
type PaymentMiddlewareFactory struct {
	wallet  wallet.Interface
	options []func(*PaymentMiddlewareConfig)
}

// NewPayment creates a new payment middleware factory, which can be used to apply payment middleware to a server.
func NewPayment(wallet wallet.Interface, opts ...func(*PaymentMiddlewareConfig)) *PaymentMiddlewareFactory {
	if wallet == nil {
		panic("wallet must be provided to create payment middleware")
	}

	return &PaymentMiddlewareFactory{
		wallet:  wallet,
		options: opts,
	}
}

// HTTPHandler creates a new payment middleware as http.Handler, which wraps the provided handler.
func (f *PaymentMiddlewareFactory) HTTPHandler(next http.Handler) http.Handler {
	return f.HTTPHandlerWithOptions(next)
}

// HTTPHandlerWithOptions creates a new payment middleware as http.Handler, which wraps the provided handler.
// Allows for additional configuration with options.
//
// This method can be useful when we have factory with default configuration for middleware,
// but we want to customize it for a specific handler (for example use different payment calculator).
func (f *PaymentMiddlewareFactory) HTTPHandlerWithOptions(next http.Handler, opts ...func(*PaymentMiddlewareConfig)) http.Handler {
	opts = append(f.options[:], opts...)

	if f.wallet == nil {
		// In case if someone would create a factory just by calling &middleware.PaymentMiddlewareFactory{}
		panic("wallet must be provided to create payment middleware")
	}

	if next == nil {
		panic("next handler must be provided to apply payment middleware to it")
	}

	return payment.NewMiddleware(next, f.wallet, opts...)
}
