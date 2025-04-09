package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// RequestData holds the request information used to create auth headers
type RequestData struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Request *http.Request
}

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
func PrepareGeneralRequestHeaders(walletInstance wallet.WalletInterface, previousResponse *transport.AuthMessage, requestData RequestData) (map[string]string, error) {
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

	writer.Write(requestID)

	request := getOrPrepareTempRequest(requestData)
	err = WriteRequestData(request, &writer)
	if err != nil {
		return nil, err
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

// WriteRequestData writes the request data into a buffer
func WriteRequestData(request *http.Request, writer *bytes.Buffer) error {
	err := WriteVarIntNum(writer, len(request.Method))
	if err != nil {
		return errors.New("failed to write method length")
	}
	writer.Write([]byte(request.Method))

	err = WriteVarIntNum(writer, len(request.URL.Path))
	if err != nil {
		return errors.New("failed to write path length")
	}
	writer.Write([]byte(request.URL.Path))

	query := request.URL.RawQuery
	if len(query) > 0 {
		searchAsArray := []byte(query)
		err = WriteVarIntNum(writer, len(searchAsArray))
		if err != nil {
			return errors.New("failed to write query length")
		}
		writer.Write([]byte(query))
	} else {
		err = WriteVarIntNum(writer, -1)
		if err != nil {
			return errors.New("failed to write -1 as query length")
		}
	}

	includedHeaders := ExtractHeaders(request.Header)
	err = WriteVarIntNum(writer, len(includedHeaders))
	if err != nil {
		return errors.New("failed to write headers length")
	}

	for _, header := range includedHeaders {
		headerKeyBytes := []byte(header[0])
		err = WriteVarIntNum(writer, len(headerKeyBytes))
		if err != nil {
			return errors.New("failed to write header key length")
		}
		writer.Write(headerKeyBytes)

		headerValueBytes := []byte(header[1])
		err = WriteVarIntNum(writer, len(headerValueBytes))
		if err != nil {
			return errors.New("failed to write header value length")
		}
		writer.Write(headerValueBytes)
	}

	err = WriteBodyToBuffer(request, writer)
	if err != nil {
		return errors.New("failed to write request body")
	}

	return nil
}

// WriteVarIntNum writes a variable-length integer to a buffer
// integer is converted to fixed size int64
func WriteVarIntNum(writer *bytes.Buffer, num int) error {
	err := binary.Write(writer, binary.LittleEndian, int64(num))
	if err != nil {
		return errors.New("failed to write varint number")
	}
	return nil
}

// ReadVarIntNum reads a variable-length integer from a buffer
func ReadVarIntNum(reader *bytes.Reader) (int64, error) {
	var intByte int64
	err := binary.Read(reader, binary.LittleEndian, &intByte)
	if err != nil {
		return 0, errors.New("failed to read varint number")
	}

	return intByte, nil
}

// ExtractHeaders extracts required headers based on conditions
func ExtractHeaders(headers http.Header) [][]string {
	var includedHeaders [][]string
	for k, v := range headers {
		k = strings.ToLower(k)
		if (strings.HasPrefix(k, "x-bsv-") || k == "content-type" || k == "authorization") &&
			!strings.HasPrefix(k, "x-bsv-auth") {
			includedHeaders = append(includedHeaders, []string{k, v[0]})
		}
	}
	return includedHeaders
}

// WriteBodyToBuffer writes the request body into a buffer
func WriteBodyToBuffer(req *http.Request, buf *bytes.Buffer) error {
	if req.Body == nil {
		err := WriteVarIntNum(buf, -1)
		if err != nil {
			return errors.New("failed to write -1 for empty body")
		}
		return nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return errors.New("failed to read request body")
	}

	if len(body) > 0 {
		err = WriteVarIntNum(buf, len(body))
		if err != nil {
			return errors.New("failed to write body length")
		}
		buf.Write(body)
		return nil
	}

	err = WriteVarIntNum(buf, -1)
	if err != nil {
		return errors.New("failed to write -1 for empty body")
	}
	return nil
}

func generateRandom() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func getOrPrepareTempRequest(requestData RequestData) *http.Request {
	if requestData.Request != nil {
		return requestData.Request
	}

	req, err := http.NewRequest(requestData.Method, requestData.URL, bytes.NewBuffer(requestData.Body))
	if err != nil {
		panic(err)
	}

	for key, value := range requestData.Headers {
		req.Header.Set(key, value)
	}

	return req
}
