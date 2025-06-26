package httptransport

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Context keys for HTTP-specific values
type contextKey string

const (
	// IdentityKey stores identity in context
	IdentityKey contextKey = "identity_key"
	// RequestKey stores request in context
	RequestKey contextKey = "http_request"
	// ResponseKey stores response writer in context
	ResponseKey contextKey = "http_response"
	// NextKey stores the next handler in context
	NextKey contextKey = "http_next_handler"
)

// Config contains configuration for HTTP transport
type Config struct {
	Wallet                 wallet.Interface
	SessionManager         auth.SessionManager
	Logger                 *slog.Logger
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived auth.OnCertificateReceivedCallback
}

// Transport implements auth.Transport for HTTP communication
type Transport struct {
	wallet                 wallet.Interface
	sessionManager         auth.SessionManager
	logger                 *slog.Logger
	messageCallback        func(context.Context, *auth.AuthMessage) error
	certificatesToRequest  *utils.RequestedCertificateSet
	onCertificatesReceived auth.OnCertificateReceivedCallback
}

// CreateHTTPTransport creates a new HTTP transport
func CreateHTTPTransport(cfg Config) auth.Transport {
	var logger *slog.Logger
	if cfg.Logger != nil {
		logger = logging.Child(cfg.Logger, "http-transport")
	} else {
		logger = slog.New(slog.DiscardHandler)
	}

	return &Transport{
		wallet:                 cfg.Wallet,
		sessionManager:         cfg.SessionManager,
		logger:                 logger,
		certificatesToRequest:  cfg.CertificatesToRequest,
		onCertificatesReceived: cfg.OnCertificatesReceived,
	}
}

// OnData registers a callback for received messages (implements auth.Transport)
func (t *Transport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	if callback == nil {
		return errors.New("callback cannot be nil")
	}

	if t.messageCallback != nil {
		t.logger.Warn("OnData callback is overriding an already registered message callback")
	}

	t.messageCallback = callback
	t.logger.Debug("Registered OnData callback")
	return nil
}

// GetRegisteredOnData returns the current callback (implements auth.Transport)
func (t *Transport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if t.messageCallback == nil {
		return nil, errors.New("no callback registered")
	}

	return t.messageCallback, nil
}

// Send sends an auth message via HTTP (implements auth.Transport)
func (t *Transport) Send(ctx context.Context, message *auth.AuthMessage) error {
	if message.IdentityKey == nil {
		return errors.New("message identity key cannot be nil")
	}

	respVal := ctx.Value(ResponseKey)
	if respVal == nil {
		return errors.New("response writer not found in context")
	}

	resp, ok := respVal.(http.ResponseWriter)
	if !ok {
		return errors.New("invalid response writer type in context")
	}

	switch message.MessageType {
	case auth.MessageTypeInitialResponse, auth.MessageTypeCertificateResponse:
		return t.sendNonGeneralMessage(resp, message)

	case auth.MessageTypeGeneral:
		return t.sendGeneralMessage(ctx, resp, message)

	case auth.MessageTypeCertificateRequest, auth.MessageTypeInitialRequest:
		return fmt.Errorf("message type %s is not supported in Send method", message.MessageType)

	default:
		return fmt.Errorf("unsupported message type: %s", message.MessageType)
	}
}

func (t *Transport) sendNonGeneralMessage(resp http.ResponseWriter, message *auth.AuthMessage) error {
	resp.Header().Set(constants.HeaderVersion, message.Version)
	resp.Header().Set(constants.HeaderMessageType, string(message.MessageType))
	resp.Header().Set(constants.HeaderIdentityKey, message.IdentityKey.ToDERHex())

	if message.Nonce != "" {
		resp.Header().Set(constants.HeaderNonce, message.Nonce)
	}

	if message.YourNonce != "" {
		resp.Header().Set(constants.HeaderYourNonce, message.YourNonce)
	}

	if message.Signature != nil {
		resp.Header().Set(constants.HeaderSignature, hex.EncodeToString(message.Signature))
	}

	t.applyDefaultCertificateRequests(message)

	resp.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(resp).Encode(message); err != nil {
		return fmt.Errorf("failed to encode message to JSON: %w", err)
	}

	return nil
}

func (t *Transport) sendGeneralMessage(ctx context.Context, resp http.ResponseWriter, message *auth.AuthMessage) error {
	req, ok := ctx.Value(RequestKey).(*http.Request)
	if !ok {
		return errors.New("invalid request type in context")
	}

	requestID := req.Header.Get(constants.HeaderRequestID)
	if requestID == "" {
		return errors.New("missing request ID for general message response")
	}

	// Set BRC-104 headers only - don't modify the payload
	resp.Header().Set(constants.HeaderVersion, message.Version)
	resp.Header().Set(constants.HeaderMessageType, string(message.MessageType))
	resp.Header().Set(constants.HeaderIdentityKey, message.IdentityKey.ToDERHex())

	if message.Nonce != "" {
		resp.Header().Set(constants.HeaderNonce, message.Nonce)
	}

	if message.YourNonce != "" {
		resp.Header().Set(constants.HeaderYourNonce, message.YourNonce)
	}

	if message.Signature != nil {
		resp.Header().Set(constants.HeaderSignature, hex.EncodeToString(message.Signature))
	}

	resp.Header().Set(constants.HeaderRequestID, requestID)

	// CRITICAL: For general messages sent via ToPeer, don't write any HTTP body
	// The message.Payload is the actual peer message, not an HTTP response
	resp.WriteHeader(http.StatusOK)

	// Don't call the next handler or write any body
	// This prevents the transport from adding HTTP response data to the payload

	return nil
}

// func (t *Transport) sendGeneralMessage(ctx context.Context, resp http.ResponseWriter, message *auth.AuthMessage) error {
// 	req, ok := ctx.Value(RequestKey).(*http.Request)
// 	if !ok {
// 		return errors.New("invalid request type in context")
// 	}

// 	requestID := req.Header.Get(constants.HeaderRequestID)
// 	if requestID == "" {
// 		return errors.New("missing request ID for general message response")
// 	}

// 	resp.Header().Set(constants.HeaderVersion, message.Version)
// 	resp.Header().Set(constants.HeaderMessageType, string(message.MessageType))
// 	resp.Header().Set(constants.HeaderIdentityKey, message.IdentityKey.ToDERHex())

// 	if message.Nonce != "" {
// 		resp.Header().Set(constants.HeaderNonce, message.Nonce)
// 	}

// 	if message.YourNonce != "" {
// 		resp.Header().Set(constants.HeaderYourNonce, message.YourNonce)
// 	}

// 	if message.Signature != nil {
// 		resp.Header().Set(constants.HeaderSignature, hex.EncodeToString(message.Signature))
// 	}

// 	resp.Header().Set(constants.HeaderRequestID, requestID)

// 	recorder := internaltransport.NewResponseRecorder(resp)
// 	nextVal := ctx.Value(NextKey)
// 	if nextVal != nil {
// 		if next, ok := nextVal.(func()); ok {
// 			next()
// 		}
// 	}
// 	statusCode := recorder.GetStatusCode()
// 	responseBody := recorder.GetBody()
// 	responseHeaders := recorder.Header()

// 	payload, err := buildResponsePayload(requestID, statusCode, responseHeaders, responseBody)
// 	if err != nil {
// 		return fmt.Errorf("failed to build response payload: %w", err)
// 	}

// 	if t.wallet != nil {
// 		if err := t.signResponse(ctx, resp, message, payload, req); err != nil {
// 			return fmt.Errorf("failed to sign response: %w", err)
// 		}
// 	}

// 	if err := recorder.Flush(); err != nil {
// 		return fmt.Errorf("failed to write response: %w", err)
// 	}

// 	return nil
// }

func (t *Transport) signResponse(ctx context.Context, resp http.ResponseWriter, message *auth.AuthMessage, payload []byte, req *http.Request) error {
	peerIdentityKeyStr := req.Header.Get(constants.HeaderIdentityKey)
	if peerIdentityKeyStr == "" {
		return fmt.Errorf("missing peer identity key in request")
	}

	peerIdentityKey, err := primitives.PublicKeyFromString(peerIdentityKeyStr)
	if err != nil {
		return fmt.Errorf("invalid peer identity key: %w", err)
	}

	signatureArgs := wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      auth.AUTH_PROTOCOL_ID,
			},
			KeyID: fmt.Sprintf("%s %s", message.Nonce, message.YourNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: peerIdentityKey,
			},
		},
		Data: payload,
	}

	signResult, err := t.wallet.CreateSignature(ctx, signatureArgs, "")
	if err != nil {
		return fmt.Errorf("failed to sign response payload: %w", err)
	}

	resp.Header().Set(constants.HeaderSignature, hex.EncodeToString(signResult.Signature.Serialize()))
	return nil
}

func (t *Transport) applyDefaultCertificateRequests(message *auth.AuthMessage) {
	if t.shouldApplyDefaultCertificates(message) {
		message.RequestedCertificates = *t.certificatesToRequest
	}
}

func (t *Transport) shouldApplyDefaultCertificates(message *auth.AuthMessage) bool {
	return message.MessageType == auth.MessageTypeInitialResponse &&
		len(message.RequestedCertificates.CertificateTypes) == 0 &&
		t.certificatesToRequest != nil
}
