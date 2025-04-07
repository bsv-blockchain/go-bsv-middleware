package utils

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

// PrepareInitialRequestBody prepares the initial request body
func PrepareInitialRequestBody(walletInstance wallet.WalletInterface) transport.AuthMessage {
	opts := wallet.GetPublicKeyOptions{IdentityKey: true}
	clientIdentityKey, err := walletInstance.GetPublicKey(context.Background(), opts)
	if err != nil {
		panic(err)
	}

	initialNonce, err := walletInstance.CreateNonce(context.Background())
	if err != nil {
		panic(err)
	}

	initialRequest := transport.AuthMessage{
		Version:      "0.1",
		MessageType:  "initialRequest",
		IdentityKey:  clientIdentityKey,
		InitialNonce: initialNonce,
	}

	return initialRequest
}

// PrepareGeneralRequestHeaders prepares the general request headers
func PrepareGeneralRequestHeaders(walletInstance wallet.WalletInterface, identityKey, initialNonce, path, method string, body []byte) (map[string]string, error) {
	serverIdentityKey := identityKey
	serverNonce := initialNonce

	opts := wallet.GetPublicKeyOptions{IdentityKey: true}
	clientIdentityKey, err := walletInstance.GetPublicKey(context.Background(), opts)
	if err != nil {
		return nil, errors.New("failed to get client identity key")
	}

	requestID := generateRandom()
	encodedRequestID := base64.StdEncoding.EncodeToString(requestID)

	newNonce, err := walletInstance.CreateNonce(context.Background())
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

	if len(body) > 0 {
		err = utils.WriteVarIntNum(&writer, len(body))
		if err != nil {
			return nil, errors.New("failed to write body length")
		}
		writer.Write(body)
	} else {
		err = utils.WriteVarIntNum(&writer, -1)
		if err != nil {
			return nil, errors.New("failed to write -1 for empty body")
		}
	}

	signature, err := walletInstance.CreateSignature(
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
