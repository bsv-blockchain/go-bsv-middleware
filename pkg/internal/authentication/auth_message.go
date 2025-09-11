package authentication

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/go-softwarelab/common/pkg/slogx"
)

var ErrGeneralMessageInNonGeneralRequest = fmt.Errorf("invalid message type")

type AuthMessageWithRequestID struct {
	*auth.AuthMessage
	RequestID      string
	RequestIDBytes []byte
}

func extractNonGeneralAuthMessage(log *slog.Logger, req *http.Request) (msg *auth.AuthMessage, err error) {
	var message auth.AuthMessage
	if err = json.NewDecoder(req.Body).Decode(&message); err != nil {
		return nil, fmt.Errorf("invalid request body: %w", err)
	}
	err = req.Body.Close()
	if err != nil {
		log.WarnContext(req.Context(), "failed to close request body", slogx.Error(err))
	}

	if message.IdentityKey == nil {
		message.IdentityKey, err = identityKeyFromHeader(req)
		if err != nil {
			return nil, fmt.Errorf("missing identity key in both body and header: %w", err)
		}
	}

	if message.MessageType == auth.MessageTypeGeneral {
		return nil, ErrGeneralMessageInNonGeneralRequest
	}

	return &message, nil
}

func extractGeneralAuthMessage(req *http.Request) (*AuthMessageWithRequestID, error) {
	version := req.Header.Get(brc104.HeaderVersion)
	if version == "" {
		return nil, ErrAuthenticationRequired
	}

	requestID, requestIDBytes, err := requestIDFromHeader(req)
	if err != nil {
		return nil, fmt.Errorf("failed to read request id: %w", err)
	}

	identityKey := req.Header.Get(brc104.HeaderIdentityKey)
	if identityKey == "" {
		return nil, fmt.Errorf("missing identity key header")
	}

	pubKey, err := primitives.PublicKeyFromString(identityKey)
	if err != nil {
		return nil, fmt.Errorf("invalid identity key format: %w", err)
	}

	signature := req.Header.Get(brc104.HeaderSignature)

	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format: %w", err)
	}

	nonce := req.Header.Get(brc104.HeaderNonce)

	yourNonce := req.Header.Get(brc104.HeaderYourNonce)

	msgPayload, err := authpayload.FromHTTPRequest(requestIDBytes, req)
	if err != nil {
		return nil, fmt.Errorf("failed to build request payload: %w", err)
	}

	requestedCertificatesJson := req.Header.Get(brc104.HeaderRequestedCertificates)

	var requestedCertificates utils.RequestedCertificateSet
	if requestedCertificatesJson != "" {
		err = json.Unmarshal([]byte(requestedCertificatesJson), &requestedCertificates)
		if err != nil {
			return nil, fmt.Errorf("invalid format of requested certificates in response: %w", err)
		}
	}

	msg := &AuthMessageWithRequestID{
		RequestID:      requestID,
		RequestIDBytes: requestIDBytes,
		AuthMessage: &auth.AuthMessage{
			Version:               version,
			MessageType:           auth.MessageTypeGeneral,
			IdentityKey:           pubKey,
			Nonce:                 nonce,
			YourNonce:             yourNonce,
			RequestedCertificates: requestedCertificates,
			Payload:               msgPayload,
			Signature:             sigBytes,
		},
	}
	return msg, nil
}

var ErrInvalidIdentityKeyFormat = fmt.Errorf("invalid identity key format")
var ErrMissingIdentityKey = fmt.Errorf("missing identity key")

func identityKeyFromHeader(req *http.Request) (*primitives.PublicKey, error) {
	identityKeyHeader := req.Header.Get(brc104.HeaderIdentityKey)
	if identityKeyHeader == "" {
		return nil, ErrMissingIdentityKey
	}

	pubKey, err := primitives.PublicKeyFromString(identityKeyHeader)
	if err != nil {
		return nil, errors.Join(ErrInvalidIdentityKeyFormat, err)
	}
	return pubKey, nil
}

var ErrInvalidRequestIDFormat = fmt.Errorf("invalid request ID format")

func requestIDFromHeader(req *http.Request) (string, []byte, error) {
	requestID := req.Header.Get(brc104.HeaderRequestID)

	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return "", nil, errors.Join(ErrInvalidRequestIDFormat, err)
	}

	return requestID, requestIDBytes, nil
}
