package httptransport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-sdk/auth"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/go-softwarelab/common/pkg/to"
)

// AuthMessageWithRequestID wraps auth.AuthMessage with a request ID
type AuthMessageWithRequestID struct {
	*auth.AuthMessage
	RequestID string
}

// ParseAuthMessageFromRequest parses auth message from HTTP request according to BRC-104
func ParseAuthMessageFromRequest(req *http.Request) (*AuthMessageWithRequestID, error) {
	if req.URL.Path == constants.WellKnownAuthPath && req.Method == http.MethodPost {
		return parseWellKnownAuthRequest(req)
	}

	return parseGeneralAuthRequest(req)
}

func parseWellKnownAuthRequest(req *http.Request) (*AuthMessageWithRequestID, error) {
	var message auth.AuthMessage
	if err := json.NewDecoder(req.Body).Decode(&message); err != nil {
		return nil, fmt.Errorf("invalid request body: %w", err)
	}

	if message.IdentityKey == nil {
		identityKeyHeader := req.Header.Get(constants.HeaderIdentityKey)
		if identityKeyHeader != "" {
			pubKey, err := primitives.PublicKeyFromString(identityKeyHeader)
			if err != nil {
				return nil, fmt.Errorf("invalid identity key format in header: %w", err)
			}
			message.IdentityKey = pubKey
		} else {
			return nil, errors.New("missing identity key in both request body and header")
		}
	}

	return &AuthMessageWithRequestID{
		AuthMessage: &message,
		RequestID:   req.Header.Get(constants.HeaderRequestID),
	}, nil
}

func parseGeneralAuthRequest(req *http.Request) (*AuthMessageWithRequestID, error) {
	version := req.Header.Get(constants.HeaderVersion)
	if version == "" {
		return nil, nil
	}

	identityKey := req.Header.Get(constants.HeaderIdentityKey)
	if identityKey == "" {
		return nil, errors.New("missing identity key header")
	}

	nonce := req.Header.Get(constants.HeaderNonce)
	yourNonce := req.Header.Get(constants.HeaderYourNonce)
	signature := req.Header.Get(constants.HeaderSignature)
	requestID := req.Header.Get(constants.HeaderRequestID)

	pubKey, err := primitives.PublicKeyFromString(identityKey)
	if err != nil {
		return nil, fmt.Errorf("invalid identity key format: %w", err)
	}

	payload, err := buildRequestPayload(req, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to build request payload: %w", err)
	}

	message := &auth.AuthMessage{
		Version:     version,
		MessageType: auth.MessageTypeGeneral,
		IdentityKey: pubKey,
		Nonce:       nonce,
		YourNonce:   yourNonce,
		Payload:     payload,
	}

	if signature != "" {
		sigBytes, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			return nil, fmt.Errorf("invalid signature format: %w", err)
		}
		message.Signature = sigBytes
	}

	return &AuthMessageWithRequestID{
		AuthMessage: message,
		RequestID:   requestID,
	}, nil
}

func buildRequestPayload(req *http.Request, requestID string) ([]byte, error) {
	writer := util.NewWriter()
	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return nil, fmt.Errorf("invalid request ID format: %w", err)
	}

	writer.WriteBytes(requestIDBytes)
	writer.WriteString(req.Method)
	writer.WriteOptionalString(req.URL.Path)
	writer.WriteOptionalString(req.URL.RawQuery)
	includedHeaders := extractIncludedHeaders(req.Header)
	includedHeadersCount, err := to.UInt64(len(includedHeaders))
	if err != nil {
		return nil, fmt.Errorf("failed to convert included headers count to uint64: %w", err)
	}

	writer.WriteVarInt(includedHeadersCount)
	for _, header := range includedHeaders {
		writer.WriteString(header[0])
		writer.WriteString(header[1])
	}
	body, err := readBody(req)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	if len(body) > 0 {
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		bodyLenght, err := to.UInt64(len(body))
		if err != nil {
			return nil, fmt.Errorf("failed to convert body length to uint64: %w", err)
		}

		writer.WriteVarInt(bodyLenght)
		writer.WriteBytes(body)
	} else {
		writer.WriteNegativeOneByte()
	}

	return writer.Buf, nil
}

func buildResponsePayload(requestID string, statusCode int, headers http.Header, body []byte) ([]byte, error) {
	writer := util.NewWriter()
	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return nil, fmt.Errorf("invalid request ID format: %w", err)
	}

	if len(requestIDBytes) != 32 {
		return nil, fmt.Errorf("request ID must be 32 bytes, got %d", len(requestIDBytes))
	}

	writer.WriteBytes(requestIDBytes)
	statusCodeUInt64, err := to.UInt64(statusCode)
	if err != nil {
		return nil, fmt.Errorf("failed to convert statuscode to uint64: %w", err)
	}

	writer.WriteVarInt(statusCodeUInt64)
	includedHeaders := extractIncludedResponseHeaders(headers)
	includedHeadersCount, err := to.UInt64(len(includedHeaders))
	if err != nil {
		return nil, fmt.Errorf("failed to convert included headers count to uint64: %w", err)
	}

	writer.WriteVarInt(includedHeadersCount)
	for _, header := range includedHeaders {
		keyBytes := []byte(header[0])
		keyBytesCount, err := to.UInt64(len(keyBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to convert header key length to uint64: %w", err)
		}

		writer.WriteVarInt(keyBytesCount)
		writer.WriteBytes(keyBytes)
		valueBytes := []byte(header[1])
		valueBytesCount, err := to.UInt64(len(valueBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to convert header value length to uint64: %w", err)
		}

		writer.WriteVarInt(valueBytesCount)
		writer.WriteBytes(valueBytes)
	}
	if len(body) > 0 {
		bodyCount, err := to.UInt64(len(body))
		if err != nil {
			return nil, fmt.Errorf("failed to convert body length to uint64: %w", err)
		}

		writer.WriteVarInt(bodyCount)
		writer.WriteBytes(body)
	} else {
		writer.WriteNegativeOneByte()
	}

	return writer.Buf, nil
}

func extractIncludedHeaders(headers http.Header) [][2]string {
	var included [][2]string
	for k, v := range headers {
		if isIncludedHeader(k) {
			included = append(included, [2]string{strings.ToLower(k), v[0]})
		}
	}
	sort.Slice(included, func(i, j int) bool {
		return included[i][0] < included[j][0]
	})
	return included
}

func extractIncludedResponseHeaders(headers http.Header) [][2]string {
	var included [][2]string
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		if (strings.HasPrefix(lowerKey, "x-bsv-") && !strings.HasPrefix(lowerKey, "x-bsv-auth-")) ||
			lowerKey == "authorization" {
			for _, value := range values {
				included = append(included, [2]string{lowerKey, value})
			}
		}
	}
	sort.Slice(included, func(i, j int) bool {
		return included[i][0] < included[j][0]
	})
	return included
}

func isIncludedHeader(headerKey string) bool {
	k := strings.ToLower(headerKey)
	return (strings.HasPrefix(k, "x-bsv-") || k == "content-type" || k == "authorization") &&
		!strings.HasPrefix(k, constants.AuthHeaderPrefix)
}

func readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	return body, nil
}
