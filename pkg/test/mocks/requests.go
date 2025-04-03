package mocks

import (
	"encoding/hex"
	globalutils "github.com/4chain-ag/go-bsv-middleware/pkg/utils"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

// Headers is a map of headers
type Headers map[string]string

// RequestBody is a placeholder for transport.AuthMessage
type RequestBody transport.AuthMessage

// WithWrongVersion adds a wrong version to the headers
func (h Headers) WithWrongVersion() {
	h["x-bsv-auth-version"] = "0.2"
}

// WithWrongSignature adds a wrong signature to the headers
func (h Headers) WithWrongSignature() {
	h["x-bsv-auth-signature"] = "wrong_signature"
}

// WithWrongSignatureInHex adds a wrong signature in hex to the headers
func (h Headers) WithWrongSignatureInHex() {
	h["x-bsv-auth-signature"] = hex.EncodeToString([]byte("wrong_signature"))
}

// WithWrongYourNonce adds a wrong your nonce to the headers
func (h Headers) WithWrongYourNonce() {
	h["x-bsv-auth-your-nonce"] = "wrong_your_nonce"
}

// WithWrongNonce adds a wrong nonce to the headers
func (h Headers) WithWrongNonce() {
	h["x-bsv-auth-nonce"] = "wrong_nonce"
}

// NewRequestBody creates a new RequestBody from an AuthMessage
func NewRequestBody(msg transport.AuthMessage) *RequestBody {
	rb := RequestBody(msg)
	return &rb
}

// WithWrongVersion adds a wrong version to the request body
func (rb *RequestBody) WithWrongVersion() *RequestBody {
	rb.Version = "0.2"
	return rb
}

// WithoutIdentityKeyAndNonce removes the identity key and nonce from the request body
func (rb *RequestBody) WithoutIdentityKeyAndNonce() *RequestBody {
	rb.IdentityKey = ""
	rb.InitialNonce = ""
	return rb
}

// AuthMessage returns the request body as an AuthMessage
func (rb *RequestBody) AuthMessage() *transport.AuthMessage {
	return (*transport.AuthMessage)(rb)
}

// PrepareInitialRequestBody prepares the initial request body
func PrepareInitialRequestBody(mockedWallet wallet.WalletInterface) *RequestBody {
	initialRequest := globalutils.PrepareInitialRequestBody(mockedWallet)

	return NewRequestBody(initialRequest)
}

// PrepareGeneralRequestHeaders prepares the general request headers
func PrepareGeneralRequestHeaders(mockedWallet wallet.WalletInterface, previousResponse *transport.AuthMessage, path, method string) (Headers, error) {
	headers, err := globalutils.PrepareGeneralRequestHeaders(mockedWallet, previousResponse, path, method)
	if err != nil {
		return nil, err
	}

	return headers, nil
}
