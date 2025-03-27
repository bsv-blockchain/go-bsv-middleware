package payment

import (
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"net/http"
)

const (
	defaultPrice = 100
)

// Options configures the payment middleware
type Options struct {
	// Wallet is used for payment processing operations
	Wallet wallet.PaymentInterface

	// CalculateRequestPrice determines the cost in satoshis
	CalculateRequestPrice func(r *http.Request) (int, error)
}

// DefaultPriceFunc returns a default pricing function
func DefaultPriceFunc(r *http.Request) (int, error) {
	return defaultPrice, nil
}
