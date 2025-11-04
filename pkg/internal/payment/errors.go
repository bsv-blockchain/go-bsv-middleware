package payment

import "net/http"

type ErrorStatus string

func (s ErrorStatus) MarshalJSON() ([]byte, error) {
	return []byte("error"), nil
}

type ErrorResponse struct {
	StatusCode  int         `json:"-"`
	Status      ErrorStatus `json:"status"`
	Code        string      `json:"code"`
	Description string      `json:"description"`
}

func (e ErrorResponse) GetStatusCode() int {
	return e.StatusCode
}

type SatoshisRequired struct {
	ErrorResponse

	SatoshisRequired int
}

// WithSatoshisRequired returns given response with satoshis required set.
//
// This needs to be value receiver, so we don't need to copy all the fields.
func (e SatoshisRequired) WithSatoshisRequired(price int) SatoshisRequired {
	e.SatoshisRequired = price
	return e
}

var (
	ErrServerMisconfigured = ErrorResponse{
		StatusCode:  http.StatusInternalServerError,
		Code:        ErrCodeServerMisconfigured,
		Description: "The payment middleware must be executed after the Auth middleware.",
	}
	ErrPaymentInternal = ErrorResponse{
		StatusCode:  http.StatusInternalServerError,
		Code:        ErrCodePaymentInternal,
		Description: "An internal error occurred while processing the payment.",
	}
	ErrMalformedPayment = ErrorResponse{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrCodeMalformedPayment,
		Description: "The X-BSV-Payment header is not valid JSON.",
	}

	ErrPaymentRequired = SatoshisRequired{
		ErrorResponse: ErrorResponse{
			StatusCode:  http.StatusPaymentRequired,
			Code:        ErrCodePaymentRequired,
			Description: "A BSV payment is required to complete this request. Provide the X-BSV-Payment header.",
		},
	}
	ErrInvalidDerivationPrefix = ErrorResponse{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrCodeInvalidPrefix,
		Description: "The X-BSV-Payment header Derivation Prefix is not valid.",
	}
	ErrInvalidDerivationSuffix = ErrorResponse{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrCodeInvalidSuffix,
		Description: "The X-BSV-Payment header Derivation Suffix is not valid. Must be base64.",
	}
	ErrPaymentFailed = ErrorResponse{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrCodePaymentFailed,
		Description: "Payment failed.",
	}
)

type ProcessingError struct {
	ErrorResponse

	Cause error `json:"-"`
}

func NewProcessingError(response ErrorResponse, cause error) *ProcessingError {
	return &ProcessingError{
		ErrorResponse: response,
		Cause:         cause,
	}
}
