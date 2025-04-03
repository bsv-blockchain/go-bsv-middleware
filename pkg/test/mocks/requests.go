package mocks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport/utils"
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
	opts := wallet.GetPublicKeyOptions{IdentityKey: true}
	clientIdentityKey, err := mockedWallet.GetPublicKey(context.Background(), opts)
	if err != nil {
		panic(err)
	}

	initialNonce, err := mockedWallet.CreateNonce(context.Background())
	if err != nil {
		panic(err)
	}

	initialRequest := transport.AuthMessage{
		Version:      "0.1",
		MessageType:  "initialRequest",
		IdentityKey:  clientIdentityKey,
		InitialNonce: initialNonce,
	}

	return NewRequestBody(initialRequest)
}

// PrepareGeneralRequestHeaders prepares the general request headers
func PrepareGeneralRequestHeaders(mockedWallet wallet.WalletInterface, previousResponse *transport.AuthMessage, path, method string) (Headers, error) {
	serverIdentityKey := previousResponse.IdentityKey
	serverNonce := previousResponse.InitialNonce

	opts := wallet.GetPublicKeyOptions{IdentityKey: true}
	clientIdentityKey, err := mockedWallet.GetPublicKey(context.Background(), opts)
	if err != nil {
		return nil, errors.New("failed to get client identity key")
	}

	requestID := generateRandom()
	encodedRequestID := base64.StdEncoding.EncodeToString(requestID)

	newNonce, err := mockedWallet.CreateNonce(context.Background())
	if err != nil {
		return nil, errors.New("failed to create new nonce")
	}

	var writer bytes.Buffer

	// Write the request ID
	writer.Write(requestID)

	// Write the method and path
	err = utils.WriteVarIntNum(&writer, len(method))
	if err != nil {
		return nil, errors.New("failed to write method length")
	}
	writer.Write([]byte(method))

	// Write the path
	err = utils.WriteVarIntNum(&writer, len(path))
	if err != nil {
		return nil, errors.New("failed to write path length")
	}
	writer.Write([]byte(path))

	// Write -1 (no query parameters)
	err = utils.WriteVarIntNum(&writer, -1)
	if err != nil {
		return nil, errors.New("failed to write query parameters length")
	}

	// Write 0 (no headers)
	err = utils.WriteVarIntNum(&writer, 0)
	if err != nil {
		return nil, errors.New("failed to write headers length")
	}

	// Write -1 (no body)
	err = utils.WriteVarIntNum(&writer, -1)
	if err != nil {
		return nil, errors.New("failed to write body length")
	}

	signature, err := mockedWallet.CreateSignature(
		context.Background(),
		writer.Bytes(),
		"auth message signature",
		fmt.Sprintf("%s %s", newNonce, serverNonce),
		serverIdentityKey,
	)
	if err != nil {
		return nil, errors.New("failed to create signature")
	}

	headers := map[string]string{
		"x-bsv-auth-version":      "0.1",
		"x-bsv-auth-identity-key": clientIdentityKey,
		"x-bsv-auth-nonce":        newNonce,
		"x-bsv-auth-your-nonce":   serverNonce,
		"x-bsv-auth-signature":    hex.EncodeToString(signature),
		"x-bsv-auth-request-id":   encodedRequestID,
	}

	return headers, nil
}

func generateRandom() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}
