package payment

import (
	"net/http"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	defaultPrice = 100
)

// Options configures the payment middleware
type Options struct {
	// Wallet is used for payment processing operations
	Wallet wallet.Interface

	// CalculateRequestPrice determines the cost in satoshis for a request
	CalculateRequestPrice func(r *http.Request) (int, error)
}

// DefaultPriceFunc returns a basic pricing function that applies a flat rate
func DefaultPriceFunc(r *http.Request) (int, error) {
	return defaultPrice, nil
}
