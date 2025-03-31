package payment

import (
	"context"
	"errors"
)

// Payment represents payment data from client
type Payment struct {
	DerivationPrefix string `json:"derivationPrefix"`
	DerivationSuffix string `json:"derivationSuffix"`
	Transaction      []byte `json:"transaction"`
}

// PaymentInfo holds information about a processed payment
type PaymentInfo struct {
	SatoshisPaid int
	Accepted     bool
	Tx           []byte
}

// contextKey is a private type for context keys
type contextKey string

// PaymentKey is the context key for payment info
const PaymentKey contextKey = "payment_info"

// PaymentVersion is the current version of the payment middleware
const PaymentVersion = "1.0"

// Common errors
var (
	ErrNoWallet              = errors.New("a valid wallet instance must be supplied to the payment middleware")
	ErrAuthMiddlewareMissing = errors.New("the payment middleware must be executed after the Auth middleware")
)

// Error codes
const (
	ErrCodeServerMisconfigured = "ERR_SERVER_MISCONFIGURED"
	ErrCodePaymentInternal     = "ERR_PAYMENT_INTERNAL"
	ErrCodePaymentRequired     = "ERR_PAYMENT_REQUIRED"
	ErrCodeMalformedPayment    = "ERR_MALFORMED_PAYMENT"
	ErrCodeInvalidPrefix       = "ERR_INVALID_DERIVATION_PREFIX"
	ErrCodePaymentFailed       = "ERR_PAYMENT_FAILED"
)

// GetPaymentInfoFromContext retrieves payment info from context
func GetPaymentInfoFromContext(ctx context.Context) (*PaymentInfo, bool) {
	info, ok := ctx.Value(PaymentKey).(*PaymentInfo)
	return info, ok
}
