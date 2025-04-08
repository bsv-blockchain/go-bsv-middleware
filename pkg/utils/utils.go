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
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// PrepareInitialRequestBody prepares the initial request body
func PrepareInitialRequestBody(walletInstance wallet.WalletInterface) transport.AuthMessage {
	opts := wallet.GetPublicKeyArgs{IdentityKey: true}
	clientIdentityKey, err := walletInstance.GetPublicKey(&opts, "")
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
		IdentityKey:  clientIdentityKey.PublicKey.ToDERHex(),
		InitialNonce: initialNonce,
	}

	return initialRequest
}

// PrepareGeneralRequestHeaders prepares the general request headers
func PrepareGeneralRequestHeaders(walletInstance wallet.WalletInterface, previousResponse *transport.AuthMessage, path, method string) (map[string]string, error) {
	serverIdentityKey := previousResponse.IdentityKey
	serverNonce := previousResponse.InitialNonce

	opts := wallet.GetPublicKeyArgs{IdentityKey: true}
	clientIdentityKey, err := walletInstance.GetPublicKey(&opts, "")
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

	// Write -1 (no body)
	err = utils.WriteVarIntNum(&writer, -1)
	if err != nil {
		return nil, errors.New("failed to write body length")
	}

	key, err := ec.PublicKeyFromString(serverIdentityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity key, %w", err)
	}

	baseArgs := wallet.EncryptionArgs{
		ProtocolID: wallet.DefaultAuthProtocol,
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: key,
		},
		KeyID: fmt.Sprintf("%s %s", newNonce, serverNonce),
	}
	createSignatureArgs := &wallet.CreateSignatureArgs{
		EncryptionArgs: baseArgs,
		Data:           writer.Bytes(),
	}

	signature, err := walletInstance.CreateSignature(createSignatureArgs, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create signature, %w", err)
	}

	headers := map[string]string{
		"x-bsv-auth-version":      "0.1",
		"x-bsv-auth-identity-key": clientIdentityKey.PublicKey.ToDERHex(),
		"x-bsv-auth-nonce":        newNonce,
		"x-bsv-auth-your-nonce":   serverNonce,
		"x-bsv-auth-signature":    hex.EncodeToString(signature.Signature.Serialize()),
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
