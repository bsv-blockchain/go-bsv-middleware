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

var (
	ErrGeneralMessageInNonGeneralRequest  = errors.New("invalid message type")
	ErrInvalidRequestBody                 = errors.New("invalid request body")
	ErrMissingIdentityKeyInBodyAndHeader  = errors.New("missing identity key in both body and header")
	ErrFailedToReadRequestID              = errors.New("failed to read request id")
	ErrMissingIdentityKeyHeader           = errors.New("missing identity key header")
	ErrInvalidIdentityKeyFormat           = errors.New("invalid identity key format")
	ErrInvalidSignatureFormat             = errors.New("invalid signature format")
	ErrFailedToBuildRequestPayload        = errors.New("failed to build request payload")
	ErrInvalidRequestedCertificatesFormat = errors.New("invalid format of requested certificates in response")
	ErrInvalidRequestIDFormat             = errors.New("invalid request ID format")
	ErrMissingIdentityKey                 = errors.New("missing identity key")
)

type AuthMessageWithRequestID struct {
	*auth.AuthMessage

	RequestID      string
	RequestIDBytes []byte
}

func extractNonGeneralAuthMessage(log *slog.Logger, req *http.Request) (msg *auth.AuthMessage, err error) {
	var message auth.AuthMessage
	if err = json.NewDecoder(req.Body).Decode(&message); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequestBody, err)
	}
	err = req.Body.Close()
	if err != nil {
		log.WarnContext(req.Context(), "failed to close request body", slogx.Error(err))
	}

	if message.IdentityKey == nil {
		message.IdentityKey, err = identityKeyFromHeader(req)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMissingIdentityKeyInBodyAndHeader, err)
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
		return nil, fmt.Errorf("%w: %w", ErrFailedToReadRequestID, err)
	}

	identityKey := req.Header.Get(brc104.HeaderIdentityKey)
	if identityKey == "" {
		return nil, ErrMissingIdentityKeyHeader
	}

	pubKey, err := primitives.PublicKeyFromString(identityKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIdentityKeyFormat, err)
	}

	signature := req.Header.Get(brc104.HeaderSignature)

	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignatureFormat, err)
	}

	nonce := req.Header.Get(brc104.HeaderNonce)

	yourNonce := req.Header.Get(brc104.HeaderYourNonce)

	msgPayload, err := authpayload.FromHTTPRequest(requestIDBytes, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToBuildRequestPayload, err)
	}

	requestedCertificatesJson := req.Header.Get(brc104.HeaderRequestedCertificates)

	var requestedCertificates utils.RequestedCertificateSet
	if requestedCertificatesJson != "" {
		err = json.Unmarshal([]byte(requestedCertificatesJson), &requestedCertificates)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequestedCertificatesFormat, err)
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

func requestIDFromHeader(req *http.Request) (string, []byte, error) {
	requestID := req.Header.Get(brc104.HeaderRequestID)

	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return "", nil, errors.Join(ErrInvalidRequestIDFormat, err)
	}

	return requestID, requestIDBytes, nil
}
