package authentication

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/httperror"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/optional"
	"github.com/go-softwarelab/common/pkg/to"
)

type Config struct {
	AllowUnauthenticated   bool
	SessionManager         auth.SessionManager
	Logger                 *slog.Logger
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived auth.OnCertificateReceivedCallback
}

type Middleware struct {
	wallet               wallet.Interface
	nextHandler          http.Handler
	log                  *slog.Logger
	allowUnauthenticated bool
	sessionManager       auth.SessionManager
	peer                 *auth.Peer
	onDataCallback       func(context.Context, *auth.AuthMessage) error
	errorHandler         func(context.Context, *slog.Logger, *httperror.Error, http.ResponseWriter, *http.Request)
}

func NewMiddleware(next http.Handler, wallet wallet.Interface, opts ...func(*Config)) *Middleware {
	cfg := to.OptionsWithDefault(Config{
		AllowUnauthenticated:   false,
		SessionManager:         auth.NewSessionManager(),
		Logger:                 slog.Default(),
		CertificatesToRequest:  nil,
		OnCertificatesReceived: nil,
	}, opts...)

	logger := logging.Child(cfg.Logger, "AuthenticationMiddleware")

	m := &Middleware{
		wallet:               wallet,
		nextHandler:          next,
		log:                  logger,
		allowUnauthenticated: cfg.AllowUnauthenticated,
		sessionManager:       cfg.SessionManager,
		errorHandler:         DefaultErrorHandler,
	}

	peerCfg := &auth.PeerOptions{
		Wallet:                wallet,
		Transport:             m,
		SessionManager:        m.sessionManager,
		CertificatesToRequest: cfg.CertificatesToRequest,
	}

	m.peer = auth.NewPeer(peerCfg)

	// auth.NewPeer should call OnData on transport,
	// that's why here we check for not nil and later we can assume that onDataCallback is not nil.
	if m.onDataCallback == nil {
		panic("peer didn't register OnData callback, this is unexpected behavior of go-sdk auth.Peer")
	}

	if cfg.OnCertificatesReceived != nil {
		m.peer.ListenForCertificatesReceived(cfg.OnCertificatesReceived)
	}

	return m
}

func (m *Middleware) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	ctx := optional.OfValue(request.Context()).OrElseGet(context.Background)
	ctx = context.WithValue(ctx, RequestKey, request)
	ctx = context.WithValue(ctx, ResponseKey, response)
	request = request.WithContext(ctx)

	log := m.log.With(slog.String("path", request.URL.Path), slog.String("method", request.Method))

	handler := m.requestHandler(request, log)

	err := handler.Handle(ctx, response, request)
	if err != nil {
		log.ErrorContext(ctx, "Failed to handle request", logging.Error(err))
		httpErr := m.toHTTPError(err)
		m.errorHandler(ctx, log, httpErr, response, request)
	}
}

// Send implementation of auth.Transport
func (m *Middleware) Send(ctx context.Context, message *auth.AuthMessage) error {
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

	//nolint:exhaustive // intentionally all the rest types are handled by default case
	switch message.MessageType {
	case auth.MessageTypeInitialResponse, auth.MessageTypeCertificateResponse:
		resp.Header().Set(brc104.HeaderVersion, message.Version)
		resp.Header().Set(brc104.HeaderMessageType, string(message.MessageType))
		resp.Header().Set(brc104.HeaderIdentityKey, message.IdentityKey.ToDERHex())

		if message.Nonce != "" {
			resp.Header().Set(brc104.HeaderNonce, message.Nonce)
		}

		if message.YourNonce != "" {
			resp.Header().Set(brc104.HeaderYourNonce, message.YourNonce)
		}

		if message.Signature != nil {
			resp.Header().Set(brc104.HeaderSignature, hex.EncodeToString(message.Signature))
		}

		m.applyDefaultCertificateRequests(message)

		resp.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(resp).Encode(message); err != nil {
			return fmt.Errorf("failed to encode message to JSON: %w", err)
		}

		return nil

	case auth.MessageTypeGeneral:
		req, ok := ctx.Value(RequestKey).(*http.Request)
		if !ok {
			return errors.New("invalid request type in context")
		}

		requestID := ""
		if req != nil {
			requestID = req.Header.Get(brc104.HeaderRequestID)
		}

		if requestID == "" {
			return errors.New("missing request ID for general message response")
		}

		resp.Header().Set(brc104.HeaderVersion, message.Version)
		resp.Header().Set(brc104.HeaderMessageType, string(message.MessageType))
		resp.Header().Set(brc104.HeaderIdentityKey, message.IdentityKey.ToDERHex())

		if message.Nonce != "" {
			resp.Header().Set(brc104.HeaderNonce, message.Nonce)
		}

		if message.YourNonce != "" {
			resp.Header().Set(brc104.HeaderYourNonce, message.YourNonce)
		}

		if message.Signature != nil {
			resp.Header().Set(brc104.HeaderSignature, hex.EncodeToString(message.Signature))
		}

		resp.Header().Set(brc104.HeaderRequestID, requestID)

		// TODO: wallet cannot be nil here
		if m.wallet != nil {
			peerIdentityKeyStr := req.Header.Get(brc104.HeaderIdentityKey)
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
				Data: message.Payload,
			}

			signResult, err := m.wallet.CreateSignature(ctx, signatureArgs, "")
			if err != nil {
				return fmt.Errorf("failed to sign response payload: %w", err)
			}

			resp.Header().Set(brc104.HeaderSignature, hex.EncodeToString(signResult.Signature.Serialize()))
		}

		return nil

	case auth.MessageTypeCertificateRequest, auth.MessageTypeInitialRequest:
		return fmt.Errorf("message type %s is not supported in Send method", message.MessageType)

	default:
		return fmt.Errorf("unsupported message type: %s", message.MessageType)
	}
}

// OnData implementation of auth.Transport.
func (m *Middleware) OnData(callback func(ctx context.Context, message *auth.AuthMessage) error) error {
	if callback == nil {
		return errors.New("callback cannot be nil")
	}

	if m.onDataCallback != nil {
		m.log.Warn("OnData callback is overriding an already registered message callback")
	}

	m.onDataCallback = callback
	m.log.Debug("Registered OnData callback")
	return nil
}

// GetRegisteredOnData implementation of auth.Transport
func (m *Middleware) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if m.onDataCallback == nil {
		return nil, errors.New("no callback registered")
	}

	return m.onDataCallback, nil
}

func (m *Middleware) applyDefaultCertificateRequests(message *auth.AuthMessage) {
	// TODO: check if this is needed
	var certificatesToRequest utils.RequestedCertificateSet

	if m.shouldApplyDefaultCertificates(message) {
		message.RequestedCertificates = certificatesToRequest
	}
}

func (m *Middleware) shouldApplyDefaultCertificates(message *auth.AuthMessage) bool {
	// TODO: check if this is needed
	var certificatesToRequest *utils.RequestedCertificateSet

	return message.MessageType == auth.MessageTypeInitialResponse &&
		len(message.RequestedCertificates.CertificateTypes) == 0 &&
		certificatesToRequest != nil
}

func (m *Middleware) requestHandler(request *http.Request, log *slog.Logger) AuthRequestHandler {
	var handler AuthRequestHandler
	if isNonGeneralRequest(request) {
		handler = &NonGeneralRequestHandler{
			log:                   log.With(slog.String("requestType", "non-general")),
			handleMessageWithPeer: m.onDataCallback,
		}
	} else {
		handler = &GeneralRequestHandler{
			log:                   log.With(slog.String("requestType", "general")),
			handleMessageWithPeer: m.onDataCallback,
			peer:                  m.peer,
			nextHandler:           m.nextHandler,
			allowUnauthenticated:  m.allowUnauthenticated,
		}
	}
	return handler
}

func isNonGeneralRequest(request *http.Request) bool {
	return request.Method == http.MethodPost && request.URL.Path == constants.WellKnownAuthPath
}

func (m *Middleware) toHTTPError(err error) *httperror.Error {
	httpErr := &httperror.Error{
		Err: err,
	}

	// To handle errors more gracefully, we need go-sdk to return specific error types
	// For now majority of errors will be treated as internal server error
	switch {
	case errors.Is(err, auth.ErrNotAuthenticated):
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Message = "Authentication failed"
	case errors.Is(err, auth.ErrMissingCertificate):
		httpErr.StatusCode = http.StatusBadRequest
		var certTypes utils.RequestedCertificateTypeIDAndFieldList
		if m.peer != nil && m.peer.CertificatesToRequest != nil {
			certTypes = m.peer.CertificatesToRequest.CertificateTypes
		}
		httpErr.Message = prepareMissingCertificateTypesErrorMsg(certTypes)
	case errors.Is(err, auth.ErrInvalidNonce):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Message = "Invalid nonce"
	case errors.Is(err, auth.ErrInvalidMessage):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Message = "Invalid message format"
	case errors.Is(err, auth.ErrSessionNotFound):
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Message = "Session not found"
	case errors.Is(err, auth.ErrInvalidSignature):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Message = "Invalid signature"
	case errors.Is(err, ErrAuthenticationRequired):
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Message = err.Error()
	case errors.Is(err, ErrGeneralMessageInNonGeneralRequest):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Message = err.Error()
	case errors.Is(err, ErrInvalidNonGeneralRequest):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Message = err.Error()
	case errors.Is(err, ErrInvalidGeneralRequest):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Message = err.Error()
	default:
		httpErr.StatusCode = http.StatusInternalServerError
		httpErr.Message = "Internal Server Error: " + err.Error()
	}

	return httpErr
}

// prepareMissingCertificateTypesErrorMsg prepares a user-friendly error message for missing certificate types.
func prepareMissingCertificateTypesErrorMsg(missingCertTypes utils.RequestedCertificateTypeIDAndFieldList) string {
	if len(missingCertTypes) == 0 {
		return ""
	}

	var typesWithFields []string
	var typesWithoutFields []string

	for certType, fields := range missingCertTypes {
		certTypeIDStr := base64.StdEncoding.EncodeToString(certType[:])
		typeName := getReadableCertTypeName(certTypeIDStr)

		if len(fields) > 0 {
			fieldStr := fmt.Sprintf("%s (fields: %s)", typeName, strings.Join(fields, ", "))
			typesWithFields = append(typesWithFields, fieldStr)
		} else {
			typesWithoutFields = append(typesWithoutFields, typeName)
		}
	}

	withFields := ""
	if len(typesWithFields) > 0 {
		withFields = " with fields"
	}
	allMissing := append(typesWithFields, typesWithoutFields...)
	return fmt.Sprintf("Missing required certificates%s: %s", withFields, strings.Join(allMissing, ", "))
}

// getReadableCertTypeName returns a shortened version of the certificate type ID for better readability.
func getReadableCertTypeName(certTypeID string) string {
	if len(certTypeID) > 16 && !strings.Contains(certTypeID, " ") {
		return certTypeID[:8] + "..." + certTypeID[len(certTypeID)-8:]
	}
	return certTypeID
}
