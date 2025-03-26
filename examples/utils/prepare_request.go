package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

func PrepareInitialRequest(mockedWallet wallet.Interface) transport.AuthMessage {
	fmt.Println("[EXAMPLE]  <---------        Preparing initial request")

	opts := wallet.GetPublicKeyOptions{IdentityKey: true}

	clientIdentityKey, err := mockedWallet.GetPublicKey(context.Background(), opts)
	if err != nil {
		panic(err)
	}

	fmt.Println("[EXAMPLE]  Client identity key:    ", clientIdentityKey)

	// Generate initial nonce
	initialNonce, err := mockedWallet.CreateNonce(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Println("[EXAMPLE]  Initial nonce:          ", initialNonce)

	initialRequest := transport.AuthMessage{
		Version:      "0.1",
		MessageType:  "initialRequest",
		IdentityKey:  clientIdentityKey,
		InitialNonce: initialNonce,
	}

	fmt.Println("[EXAMPLE]  Initial request:        ", initialRequest)

	return initialRequest
}

func PreparePingRequest(req *http.Request, mockedWallet wallet.Interface, res *transport.AuthMessage) {
	fmt.Println("[EXAMPLE]  <---------               Preparing ping request")

	serverIdentityKey := res.IdentityKey
	serverNonce := res.InitialNonce

	fmt.Println("[EXAMPLE]  Server identity key:    ", serverIdentityKey)
	fmt.Println("[EXAMPLE]  Server nonce:           ", serverNonce)

	requestID := generateRandom()
	encodedRequestID := base64.StdEncoding.EncodeToString(requestID)

	newNonce, err := mockedWallet.CreateNonce(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Println("[EXAMPLE]  Request ID bytes:       ", requestID)
	fmt.Println("[EXAMPLE]  Request ID base64:      ", encodedRequestID)
	fmt.Println("[EXAMPLE]  New nonce:              ", newNonce)

	var writer bytes.Buffer

	writer.Write(requestID)

	writeVarIntNum(&writer, int64(len("GET")))
	writer.Write([]byte("GET"))

	writeVarIntNum(&writer, int64(len("/ping")))
	writer.Write([]byte("/ping"))

	// Write -1 (no query parameters)
	writeVarIntNum(&writer, -1)

	// Write 0 (no headers)
	writeVarIntNum(&writer, 0)

	// Write -1 (no body)
	writeVarIntNum(&writer, -1)

	fmt.Println("[EXAMPLE]  Request data:           ", writer.Bytes())

	signature, err := mockedWallet.CreateSignature(
		context.Background(),
		writer.Bytes(),
		"auth message signature",
		fmt.Sprintf("%s %s", newNonce, serverNonce),
		serverIdentityKey,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("[EXAMPLE]  Signature:              ", signature)
	fmt.Println("[EXAMPLE]  Signature:              ", string(signature))
	fmt.Println("[EXAMPLE]  Signature HEX:          ", hex.EncodeToString(signature))

	headers := map[string]string{
		"x-bsv-auth-version":      "0.1",
		"x-bsv-auth-identity-key": res.IdentityKey,
		"x-bsv-auth-nonce":        newNonce,
		"x-bsv-auth-your-nonce":   serverNonce,
		"x-bsv-auth-signature":    hex.EncodeToString(signature),
		"x-bsv-auth-request-id":   encodedRequestID,
	}

	fmt.Println("[EXAMPLE]  All headers:               ")

	for k, v := range headers {
		fmt.Println("[EXAMPLE]  Header:                 ", k, ":", v)
		req.Header.Set(k, v)
	}
}

func generateRandom() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// writeVarIntNum writes a variable-length integer into a buffer
func writeVarIntNum(buf *bytes.Buffer, value int64) {
	if value < 0 {
		binary.Write(buf, binary.LittleEndian, int8(-1))
	} else {
		binary.Write(buf, binary.LittleEndian, uint64(value))
	}
}
