package payment

import (
	"net/http"
)

const (
	defaultPrice = 100
)

// DefaultPriceFunc returns a basic pricing function that applies a flat rate
func DefaultPriceFunc(_ *http.Request) (int, error) {
	return defaultPrice, nil
}
