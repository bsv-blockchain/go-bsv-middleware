package wallet

import (
	"context"
	
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// MockPaymentWallet implements wallet.PaymentInterface for testing
type MockPaymentWallet struct {
	*Wallet

	InternalizeActionCalled bool
	InternalizeActionArgs   InternalizeActionArgs
	InternalizeActionResult InternalizeActionResult
	InternalizeActionError  error
}

// NewMockPaymentWallet creates a new payment-capable mock wallet
func NewMockPaymentWallet(key *ec.PrivateKey) *MockPaymentWallet {
	return &MockPaymentWallet{
		Wallet: NewMockWallet(key).(*Wallet),
		InternalizeActionResult: InternalizeActionResult{
			Accepted: true,
		},
	}
}

// InternalizeAction implements wallet.PaymentInterface
func (m *MockPaymentWallet) InternalizeAction(ctx context.Context, args InternalizeActionArgs) (InternalizeActionResult, error) {
	m.InternalizeActionCalled = true
	m.InternalizeActionArgs = args

	if m.InternalizeActionError != nil {
		return InternalizeActionResult{}, m.InternalizeActionError
	}

	return m.InternalizeActionResult, nil
}

// SetInternalizeActionError configures error response
func (m *MockPaymentWallet) SetInternalizeActionError(err error) {
	m.InternalizeActionError = err
}

// SetInternalizeActionResult configures result
func (m *MockPaymentWallet) SetInternalizeActionResult(result InternalizeActionResult) {
	m.InternalizeActionResult = result
}
