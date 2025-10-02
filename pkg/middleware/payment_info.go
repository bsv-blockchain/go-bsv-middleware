package middleware

import (
	"context"
	"fmt"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/payctx"
)

// PaymentInfo holds information about a processed payment stored in the request context
type PaymentInfo = payctx.Payment

// ShouldGetPaymentInfo returns the payment info from the context.
// Returns an error if the context does not contain a payment, which indicates a potentially invalid server setup.
func ShouldGetPaymentInfo(ctx context.Context) (*PaymentInfo, error) {
	info, err := payctx.ShouldGetPayment(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve payment info from context: %w", err)
	}
	return info, nil
}
