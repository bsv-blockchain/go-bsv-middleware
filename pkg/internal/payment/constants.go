package payment

// DPP Protocol Constants
const (
	// PaymentVersion is the version of the DPP protocol implementation
	PaymentVersion = "1.0"

	PaymentOriginator = "paymentMiddleware"
)

// HTTP Header constants
const (
	// HeaderPayment is the header used to transmit payment data
	HeaderPayment = "X-BSV-Payment"

	// HeaderVersion is the header for the payment protocol version
	HeaderVersion = "X-BSV-Payment-Version"

	// HeaderSatoshisRequired is the header for required payment amount
	HeaderSatoshisRequired = "X-BSV-Payment-Satoshis-Required"

	// HeaderSatoshisPaid is the header for the amount that was paid
	HeaderSatoshisPaid = "X-BSV-Payment-Satoshis-Paid"

	// HeaderDerivationPrefix is the header for the derivation prefix
	HeaderDerivationPrefix = "X-BSV-Payment-Derivation-Prefix"
)

// Error codes
const (
	// ErrCodeServerMisconfigured indicates middleware configuration issues
	ErrCodeServerMisconfigured = "ERR_SERVER_MISCONFIGURED"

	// ErrCodePaymentInternal indicates internal payment processing errors
	ErrCodePaymentInternal = "ERR_PAYMENT_INTERNAL"

	// ErrCodePaymentRequired indicates payment is needed for the resource
	ErrCodePaymentRequired = "ERR_PAYMENT_REQUIRED"

	// ErrCodeMalformedPayment indicates invalid payment data format
	ErrCodeMalformedPayment = "ERR_MALFORMED_PAYMENT"

	// ErrCodeInvalidPrefix indicates an invalid derivation prefix
	ErrCodeInvalidPrefix = "ERR_INVALID_DERIVATION_PREFIX"

	// ErrCodeInvalidSuffix indicates an invalid derivation suffix
	ErrCodeInvalidSuffix = "ERR_INVALID_DERIVATION_SUFFIX"

	// ErrCodePaymentFailed indicates a payment processing failure
	ErrCodePaymentFailed = "ERR_PAYMENT_FAILED"
)
