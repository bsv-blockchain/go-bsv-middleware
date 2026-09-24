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
	"os"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/slogx"
	"github.com/go-softwarelab/common/pkg/to"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/authctx"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/httperror"
)

const WellKnownAuthPath = "/.well-known/auth"

var (
	ErrPeerSendingMessageWithoutIdentityKey = errors.New("peer is trying to send message without identity key")
	ErrMissingRequestIDInGeneralMessage     = errors.New("missing request ID in general message request")
	ErrUnsupportedMessageTypeInSend         = errors.New("message type is not supported in auth middleware Send method")
	ErrCallbackCannotBeNil                  = errors.New("callback cannot be nil")
	ErrNoCallbackRegistered                 = errors.New("no callback registered")
)

type Config struct {
	AllowUnauthenticated   bool
	SessionManager         auth.SessionManager
	Logger                 *slog.Logger
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived auth.OnCertificateReceivedCallback
	// CertificateWaitTimeout bounds how long a general request will wait for
	// a concurrently in-flight certificate exchange to complete before
	// failing with CERTIFICATE_TIMEOUT (see certificate_wait.go). It only has
	// any effect when both CertificatesToRequest requires certificates and
	// OnCertificatesReceived is set. Zero means DefaultCertificateWaitTimeout.
	CertificateWaitTimeout time.Duration
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
	// certWaitGate is non-nil only when the server both requests certificates
	// and registers Config.OnCertificatesReceived - see NewMiddleware and
	// certificate_wait.go. It lets GeneralRequestHandler hold a protected
	// request open until a concurrent handshake's certificate exchange
	// completes, instead of failing it immediately, mirroring the TS
	// reference's certificate-wait behaviour (auth-express-middleware's
	// ExpressTransport#scheduleNextOrCertificateWait).
	certWaitGate *certificateWaitGate
}

func NewMiddleware(next http.Handler, wallet wallet.Interface, opts ...func(*Config)) *Middleware {
	cfg := to.OptionsWithDefault(Config{
		AllowUnauthenticated:   false,
		SessionManager:         auth.NewSessionManager(),
		Logger:                 slog.Default(),
		CertificatesToRequest:  nil,
		OnCertificatesReceived: nil,
	}, opts...)

	logger := slogx.Child(cfg.Logger, "AuthenticationMiddleware")

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
		Logger:                logger,
	}

	m.peer = auth.NewPeer(peerCfg)

	// auth.NewPeer should call OnData on transport,
	// that's why here we check for not nil and later we can assume that onDataCallback is not nil.
	if m.onDataCallback == nil {
		logger.Error("peer didn't register OnData callback, this is unexpected behavior of go-sdk auth.Peer")
		// This is a critical error that indicates a programming error or incompatible SDK version
		os.Exit(1)
	}

	if cfg.OnCertificatesReceived != nil {
		listener := cfg.OnCertificatesReceived

		// Only require certificate approval when the server actually
		// requires certificates before authenticating a session (matching
		// go-sdk's own gating condition in handleInitialRequest: it flips a
		// new session's IsAuthenticated to false, the precondition for
		// auth.ErrNotAuthenticated, exactly when CertificateTypes is
		// non-empty). Otherwise auth.ErrNotAuthenticated can never occur for
		// this server, so the wait gate would never be consulted anyway -
		// this check just avoids allocating it needlessly.
		requiresCertificates := cfg.CertificatesToRequest != nil && len(cfg.CertificatesToRequest.CertificateTypes) > 0
		if requiresCertificates {
			waitTimeout := cfg.CertificateWaitTimeout
			if waitTimeout <= 0 {
				waitTimeout = DefaultCertificateWaitTimeout
			}
			m.certWaitGate = newCertificateWaitGate(waitTimeout)
			gate := m.certWaitGate
			listener = func(ctx context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
				err := cfg.OnCertificatesReceived(ctx, senderPublicKey, certs)
				// go-sdk's Peer only invokes this callback after it has
				// already marked the session authenticated (see
				// auth.Peer.handleCertificateResponse), so the exchange is
				// "complete" from a waiting request's point of view
				// regardless of what the application's own callback decides
				// to do with it.
				gate.notify(senderPublicKey.ToDERHex())
				return err
			}
		}

		m.peer.ListenForCertificatesReceived(listener)
	}

	return m
}

func (m *Middleware) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	ctx = authctx.WithRequest(ctx, request)
	ctx = authctx.WithResponse(ctx, response)
	request = request.WithContext(ctx)

	log := m.log.With(slog.String("path", request.URL.Path), slog.String("method", request.Method))

	handler := m.requestHandler(request, log)

	err := handler.Handle(ctx, response, request)
	if err != nil {
		httpErr := m.toHTTPError(err)
		m.errorHandler(ctx, log, httpErr, response, request)
	}
}

// Send implementation of auth.Transport, will be called by middleware peer whenever it wants to send some response.
func (m *Middleware) Send(ctx context.Context, message *auth.AuthMessage) error {
	log := m.log.With(logging.AuthMessage(message))

	log.DebugContext(ctx, "Preparing response based on auth message")

	if message.IdentityKey == nil {
		return ErrPeerSendingMessageWithoutIdentityKey
	}

	resp, err := authctx.ShouldGetResponse(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve response writer in transport: %w", err)
	}

	var body []byte
	//nolint:exhaustive // intentionally all the rest types are handled by default case
	switch message.MessageType {
	case auth.MessageTypeInitialResponse, auth.MessageTypeCertificateResponse:
		resp.Header().Set("Content-Type", "application/json")

		body, err = json.Marshal(message)
		if err != nil {
			return fmt.Errorf("failed to encode message to JSON: %w", err)
		}

	case auth.MessageTypeGeneral:
		req, reqErr := authctx.ShouldGetRequest(ctx)
		if reqErr != nil {
			return fmt.Errorf("failed to retrieve request in transport: %w", reqErr)
		}

		requestID := req.Header.Get(brc104.HeaderRequestID)
		if requestID == "" {
			return ErrMissingRequestIDInGeneralMessage
		}

		resp.Header().Set(brc104.HeaderRequestID, requestID)

		log = log.With(logging.RequestID(requestID))

	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedMessageTypeInSend, message.MessageType)
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

	log.DebugContext(ctx, "Sending response")
	resp.WriteHeader(http.StatusOK)
	_, err = resp.Write(body)
	if err != nil {
		log.ErrorContext(ctx, "Failed to write response body", slogx.Error(err), slog.String("body", string(body)))
		// if we cannot write the response body, then we can't do anything more about the error, beside logging it.
		return nil
	}

	return nil
}

// OnData implementation of auth.Transport.
// It is meant to be called by Peer to register a callback on received data by the transport.
func (m *Middleware) OnData(callback func(ctx context.Context, message *auth.AuthMessage) error) error {
	if callback == nil {
		return ErrCallbackCannotBeNil
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
		return nil, ErrNoCallbackRegistered
	}

	return m.onDataCallback, nil
}

func (m *Middleware) requestHandler(request *http.Request, log *slog.Logger) AuthRequestHandler {
	if isNonGeneralRequest(request) {
		return &NonGeneralRequestHandler{
			log:                   log.With(slog.String("requestType", "non-general")),
			handleMessageWithPeer: m.onDataCallback,
		}
	}
	return &GeneralRequestHandler{
		log:                   log.With(slog.String("requestType", "general")),
		handleMessageWithPeer: m.onDataCallback,
		peer:                  m.peer,
		nextHandler:           m.nextHandler,
		allowUnauthenticated:  m.allowUnauthenticated,
		certWaitGate:          m.certWaitGate,
	}
}

func isNonGeneralRequest(request *http.Request) bool {
	return request.Method == http.MethodPost && request.URL.Path == WellKnownAuthPath
}

func (m *Middleware) toHTTPError(err error) *httperror.Error {
	httpErr := &httperror.Error{
		Err: err,
	}

	// To handle errors more gracefully, we need go-sdk to return specific error types
	// For now majority of errors will be treated as internal server error
	//
	// Status codes and Code values below mirror the BRC-103/BRC-104 wire error
	// shape emitted by the TS reference (auth-express-middleware): a missing or
	// incomplete authentication attempt is UNAUTHORIZED (401), while a
	// well-formed attempt that fails cryptographic verification is
	// ERR_AUTH_FAILED (401). ErrMissingCertificate keeps its own code since it
	// carries a bespoke, actionable message about which certificates are
	// needed.
	switch {
	case errors.Is(err, ErrCertificateTimeout):
		// Checked ahead of auth.ErrNotAuthenticated below: a certificate-wait
		// timeout's error chain also wraps the auth.ErrNotAuthenticated that
		// triggered the wait in the first place (see
		// GeneralRequestHandler.processMessageWithCertificateWait), so this
		// more specific case must be matched first.
		httpErr.StatusCode = http.StatusRequestTimeout
		httpErr.Code = codeCertificateTimeout
		httpErr.Message = "Certificate request timed out"

	case errors.Is(err, ErrCertificateWaitAtCapacity):
		// Checked ahead of auth.ErrNotAuthenticated below for the same reason
		// as ErrCertificateTimeout above: this error chain also wraps it.
		// Mirrors the TS reference's own capacity response
		// (auth-express-middleware's assertPendingCapacity /
		// respondWithProtocolError: 503 ERR_AUTH_CAPACITY).
		httpErr.StatusCode = http.StatusServiceUnavailable
		httpErr.Code = "ERR_AUTH_CAPACITY"
		httpErr.Message = "Authentication is temporarily at capacity"

	case errors.Is(err, auth.ErrReplayedNonce):
		// Maintainer decision: match the conformance corpus's documented
		// BRC-103/BRC-104 wire behaviour for a replayed nonce
		// (auth.brc31-handshake.14 expects 401/ERR_AUTH_FAILED) on both the
		// general-message path - where the TS reference's own
		// regex-based classification already produces this
		// (auth-express-middleware's handleGeneralMessage:
		// /nonce|signature|session|auth version/i over the error message ->
		// 401 ERR_AUTH_FAILED) - and the /.well-known/auth handshake path.
		// The TS reference middleware's handshake path currently
		// returns 500 ERR_INTERNAL_SERVER_ERROR unconditionally for *any*
		// handshake failure, including a replayed initialRequest
		// (handleWellKnownAuth's messageCallback .catch() does no
		// message-based classification at all) - this is a known upstream
		// inconsistency between the two paths in the TS reference itself,
		// not something this mapping should reproduce.
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = "ERR_AUTH_FAILED"
		httpErr.Message = "Authentication failed"

	case errors.Is(err, ErrMissingIdentityKeyInBodyAndHeader):
		// Checked ahead of the broader ErrInvalidNonGeneralRequest case below:
		// a /.well-known/auth initialRequest with no identity key at all is an
		// incomplete authentication attempt, not a malformed request.
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = codeUnauthorized
		httpErr.Message = "Authentication failed: missing identity key"

	case errors.Is(err, auth.ErrNotAuthenticated):
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = codeUnauthorized
		httpErr.Message = "Authentication failed"

	case errors.Is(err, auth.ErrMissingCertificate):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Code = "ERR_CERTIFICATES_REQUIRED"
		var certTypes utils.RequestedCertificateTypeIDAndFieldList
		if m.peer != nil && m.peer.CertificatesToRequest != nil {
			certTypes = m.peer.CertificatesToRequest.CertificateTypes
		}
		httpErr.Message = prepareMissingCertificateTypesErrorMsg(certTypes)

	case errors.Is(err, auth.ErrInvalidNonce):
		// Covers both a missing/invalid initialNonce on the handshake and a
		// general message whose yourNonce isn't a nonce we issued - both are
		// "you aren't (yet) authenticated" rather than a generic bad request.
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = codeUnauthorized
		httpErr.Message = "Invalid nonce"

	case errors.Is(err, auth.ErrInvalidMessage):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Code = "ERR_AUTH_MALFORMED"
		httpErr.Message = "Invalid message format"

	case errors.Is(err, auth.ErrSessionNotFound):
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = codeUnauthorized
		httpErr.Message = "Session not found"

	case errors.Is(err, auth.ErrInvalidSignature):
		// A structurally valid message whose signature does not verify: the
		// attempt was complete but cryptographically rejected.
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = "ERR_AUTH_FAILED"
		httpErr.Message = "Invalid signature"

	case errors.Is(err, ErrResponseSigningFailed):
		httpErr.StatusCode = http.StatusInternalServerError
		httpErr.Code = "ERR_RESPONSE_SIGNING_FAILED"
		httpErr.Message = "Failed to sign the authenticated response"

	case errors.Is(err, ErrAuthenticationRequired):
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = codeUnauthorized
		httpErr.Message = err.Error()

	case errors.Is(err, ErrGeneralMessageInNonGeneralRequest):
		httpErr.StatusCode = http.StatusBadRequest
		httpErr.Code = "ERR_AUTH_MALFORMED"
		httpErr.Message = err.Error()

	case errors.Is(err, ErrInvalidNonGeneralRequest):
		// /.well-known/auth is exclusively a BRC-103 handshake endpoint: a body
		// that can't be decoded as an AuthMessage (e.g. identityKey missing or
		// not a valid public key, per auth.AuthMessage's own UnmarshalJSON) is
		// an incomplete/invalid authentication attempt, not a generic bad
		// request.
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = codeUnauthorized
		httpErr.Message = err.Error()

	case errors.Is(err, ErrInvalidGeneralRequest):
		// The request claimed to carry BRC-104 auth headers (it reached the
		// general-message path at all) but they were missing/malformed, e.g.
		// no signature or request-id header: an incomplete authentication
		// attempt, not a generic bad request.
		httpErr.StatusCode = http.StatusUnauthorized
		httpErr.Code = codeUnauthorized
		httpErr.Message = err.Error()

	default:
		httpErr.StatusCode = http.StatusInternalServerError
		httpErr.Code = "ERR_INTERNAL_SERVER_ERROR"
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
