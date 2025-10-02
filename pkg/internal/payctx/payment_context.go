package payctx

import (
	"context"
	"fmt"
	"slices"
)

// Payment holds information about a processed payment stored in the request context
type Payment struct { //nolint: revive // Ignore that struct starts with package name
	// SatoshisPaid is the amount paid in satoshis
	SatoshisPaid int
	// Accepted indicates whether the payment was accepted
	Accepted bool
	// Tx is the payment transaction data
	Tx []byte
}

// contextKey is a private type for context keys
type contextKey string

// PaymentKey is the context key for payment info
const paymentKey contextKey = "payment"

func WithPayment(ctx context.Context, info *Payment) context.Context {
	payment := Payment{
		SatoshisPaid: info.SatoshisPaid,
		Accepted:     info.Accepted,
		Tx:           slices.Clone(info.Tx),
	}

	return context.WithValue(ctx, paymentKey, payment)
}

func WithoutPayment(ctx context.Context) context.Context {
	return context.WithValue(ctx, paymentKey, Payment{SatoshisPaid: 0})
}

// ShouldGetPayment retrieves payment info from context
func ShouldGetPayment(ctx context.Context) (*Payment, error) {
	contextValue := ctx.Value(paymentKey)
	if contextValue == nil {
		return nil, fmt.Errorf("%s not found in context", paymentKey)
	}

	payment, ok := contextValue.(Payment)
	if !ok {
		return nil, fmt.Errorf("%s contains unexpected type %T", paymentKey, contextValue)
	}

	return &payment, nil
}
