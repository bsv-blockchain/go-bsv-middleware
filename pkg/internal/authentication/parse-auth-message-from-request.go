package authentication

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// AuthMessageWithRequestID wraps auth.AuthMessage with a request ID.
type AuthMessageWithRequestID struct {
	*auth.AuthMessage
	RequestID      string
	RequestIDBytes []byte
}

// ParseAuthMessageFromRequest parses auth message from HTTP request.
func ParseAuthMessageFromRequest(req *http.Request) (*AuthMessageWithRequestID, error) {
	requestID := req.Header.Get(brc104.HeaderRequestID)
	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return nil, fmt.Errorf("invalid request ID format: %w", err)
	}

	if req.URL.Path == constants.WellKnownAuthPath && req.Method == http.MethodPost {
		var message auth.AuthMessage
		if err := json.NewDecoder(req.Body).Decode(&message); err != nil {
			return nil, fmt.Errorf("invalid request body: %w", err)
		}

		if message.IdentityKey == nil {
			identityKeyHeader := req.Header.Get(brc104.HeaderIdentityKey)
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
		msg := &AuthMessageWithRequestID{
			RequestID:      requestID,
			RequestIDBytes: requestIDBytes,
			AuthMessage:    &message,
		}
		return msg, nil
	}

	version := req.Header.Get(brc104.HeaderVersion)
	if version == "" {
		return nil, nil
	}

	identityKey := req.Header.Get(brc104.HeaderIdentityKey)
	if identityKey == "" {
		return nil, errors.New("missing identity key header")
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
