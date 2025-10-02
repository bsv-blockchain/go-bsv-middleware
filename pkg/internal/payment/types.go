package payment

// Payment represents the client payment data sent by the payer
type Payment struct {
	// ModeID is the identifier for the payment mode
	ModeID string `json:"modeId"`
	// DerivationPrefix is the prefix for the payment address
	DerivationPrefix string `json:"derivationPrefix"`
	// DerivationSuffix is the suffix for the payment address
	DerivationSuffix string `json:"derivationSuffix"`
	// Transaction is the payment transaction data
	Transaction []byte `json:"transaction"`
}

type Response interface {
	GetStatusCode() int
}
