package mocks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport/utils"
)

type Headers map[string]string
type RequestBody transport.AuthMessage

func (h Headers) WithWrongVersion() {
	h["x-bsv-auth-version"] = "0.2"
}

func (h Headers) WithWrongSignature() {
	h["x-bsv-auth-signature"] = "wrong_signature"
}

func (h Headers) WithWrongSignatureInHex() {
	h["x-bsv-auth-signature"] = hex.EncodeToString([]byte("wrong_signature"))
}

func (h Headers) WithWrongYourNonce() {
	h["x-bsv-auth-your-nonce"] = "wrong_your_nonce"
}

func (h Headers) WithWrongNonce() {
	h["x-bsv-auth-nonce"] = "wrong_nonce"
}

func (rb *RequestBody) WithWrongVersion() *RequestBody {
	rb.Version = "0.2"
	return rb
}

func (rb *RequestBody) WithoutIdentityKeyAndNonce() *RequestBody {
	rb.IdentityKey = ""
	rb.InitialNonce = ""
	return rb
}

func (rb *RequestBody) AuthMessage() *transport.AuthMessage {
	return (*transport.AuthMessage)(rb)
}

func NewRequestBody(msg transport.AuthMessage) *RequestBody {
	rb := RequestBody(msg)
	return &rb
}

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

func PrepareGeneralRequestHeaders(mockedWallet wallet.WalletInterface, previousResponse *transport.AuthMessage) (Headers, error) {
	serverIdentityKey := previousResponse.IdentityKey
	serverNonce := previousResponse.InitialNonce

	opts := wallet.GetPublicKeyOptions{IdentityKey: true}
	clientIdentityKey, err := mockedWallet.GetPublicKey(context.Background(), opts)
	if err != nil {
		return nil, err
	}

	requestID := generateRandom()
	encodedRequestID := base64.StdEncoding.EncodeToString(requestID)

	newNonce, err := mockedWallet.CreateNonce(context.Background())
	if err != nil {
		return nil, err
	}

	var writer bytes.Buffer

	// Write the request ID
	writer.Write(requestID)

	// Write the method and path
	utils.WriteVarIntNum(&writer, len("GET"))
	writer.Write([]byte("GET"))

	// Write the path
	utils.WriteVarIntNum(&writer, len("/ping"))
	writer.Write([]byte("/ping"))

	// Write -1 (no query parameters)
	utils.WriteVarIntNum(&writer, -1)

	// Write 0 (no headers)
	utils.WriteVarIntNum(&writer, 0)

	// Write -1 (no body)
	utils.WriteVarIntNum(&writer, -1)

	signature, err := mockedWallet.CreateSignature(
		context.Background(),
		writer.Bytes(),
		"auth message signature",
		fmt.Sprintf("%s %s", newNonce, serverNonce),
		serverIdentityKey,
	)
	if err != nil {
		return nil, err
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
