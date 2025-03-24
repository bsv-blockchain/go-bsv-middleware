package wallet

// Constants for expected return values
const (
	// IdentityKeyMock is the expected identity key
	IdentityKeyMock = "02mockidentitykey0000000000000000000000000000000000000000000000000000000"
	// DerivedKeyMock is the expected derived key
	DerivedKeyMock = "02mockderivedkey0000000000000000000000000000000000000000000000000000000"
	// MockSignature is the expected signature
	MockSignature = "mocksignaturedata"
	// MockNonce is the expected nonce
	MockNonce = "mocknonce12345"

	// TODO: be replaced with actual error messages from the wallet package

	// ErrorNoPrivilege is the error message for no privilege support
	ErrorNoPrivilege = "no privilege support"
	// ErrorKeyDeriver is the error message for key deriver not initialized
	ErrorKeyDeriver = "keyDeriver is not initialized"
	// ErrorMissingParams is the error message for missing parameters
	ErrorMissingParams = "protocolID and keyID are required if identityKey is false or undefined"
	// ErrorInvalidInput is the error message for invalid input
	ErrorInvalidInput = "invalid input"
)

// Constants for mock setup
const (
	// WithKeyDeriver is a flag to initialize the key deriver
	WithKeyDeriver = true
	// WithoutKeyDeriver is a flag to not initialize the key deriver
	WithoutKeyDeriver = false
)
