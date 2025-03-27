package wallet

import "context"

// PaymentRemittance contains payment metadata
type PaymentRemittance struct {
	DerivationPrefix  string `json:"derivationPrefix"`
	DerivationSuffix  string `json:"derivationSuffix"`
	SenderIdentityKey string `json:"senderIdentityKey"`
}

// InternalizeOutput describes an output to process
type InternalizeOutput struct {
	OutputIndex       int                `json:"outputIndex"`
	Protocol          string             `json:"protocol"`
	PaymentRemittance *PaymentRemittance `json:"paymentRemittance,omitempty"`
}

// InternalizeActionArgs contains parameters for internalizing a transaction
type InternalizeActionArgs struct {
	Tx          []byte              `json:"tx"`
	Outputs     []InternalizeOutput `json:"outputs"`
	Description string              `json:"description"`
	Labels      []string            `json:"labels,omitempty"`
}

// InternalizeActionResult represents the result
type InternalizeActionResult struct {
	Accepted bool `json:"accepted"`
}

// PaymentInterface extends the basic wallet interface with payment-specific methods
type PaymentInterface interface {
	Interface

	// InternalizeAction processes a received payment transaction
	InternalizeAction(ctx context.Context, args InternalizeActionArgs) (InternalizeActionResult, error)
}
