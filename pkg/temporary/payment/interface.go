package payment

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// PaymentInterface extends the basic wallet interface with payment-specific methods.
type PaymentInterface interface {
	wallet.AuthOperations

	// InternalizeAction processes a received payment transaction
	InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs) (wallet.InternalizeActionResult, error)
}
