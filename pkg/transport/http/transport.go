package httptransport

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/util"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type contextKey string

// IdentityKey stores identity in context.
const IdentityKey contextKey = "identity_key"

// RequestKey stores request in context.
const RequestKey contextKey = "http_request"

// ResponseKey stores response writer in context.
const ResponseKey contextKey = "http_response"

// NextKey stores the next handler in context.
const NextKey contextKey = "http_next_handler"

// TODO: Move to pkg/internal/transport
// ResponseRecorder is a custom http.ResponseWriter that records the response status code and body.
type ResponseRecorder struct {
	http.ResponseWriter
	written    bool
	statusCode int
	body       []byte
}

// GetBody retrieves the recorded response body.
func (r *ResponseRecorder) GetBody() []byte {
	return r.body
}

// WriteHeader captures the status code
func (r *ResponseRecorder) WriteHeader(statusCode int) {
	if r.written {
		return
	}

	if statusCode == 0 {
		statusCode = http.StatusInternalServerError
	}
	r.statusCode = statusCode
	r.written = true
}

// Write captures the response body and ensures that WriteHeader is called at least once.
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.WriteHeader(http.StatusOK)
	}
	r.body = append(r.body, b...)
	return len(b), nil
}

// Flush writes the response header and body if they have not been written yet.
func (r *ResponseRecorder) Flush() error {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	r.ResponseWriter.WriteHeader(r.statusCode)
	if len(r.body) > 0 {
		_, err := r.ResponseWriter.Write(r.body)
		return err
	}

	return nil
}

// HasBeenWritten checks if the response has been written.
func (r *ResponseRecorder) HasBeenWritten() bool {
	return r.written
}

// WrapResponseWriter wraps and tracks write status.
func WrapResponseWriter(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     0,
	}
}

// GetStatusCode retrieves the status code from the ResponseRecorder.
func (r *ResponseRecorder) GetStatusCode() int {
	return r.statusCode
}

// TransportConfig config for Transport.
type TransportConfig struct {
	Wallet                 interfaces.Wallet
	SessionManager         auth.SessionManager
	Logger                 *slog.Logger
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived auth.OnCertificateReceivedCallback
}

// Transport is an HTTP-based auth transport.
type Transport struct {
	wallet                 interfaces.Wallet
	sessionManager         auth.SessionManager
	logger                 *slog.Logger
	messageCallback        func(context.Context, *auth.AuthMessage) error
	certificatesToRequest  *utils.RequestedCertificateSet
	onCertificatesReceived auth.OnCertificateReceivedCallback
}

// New creates a new Transport.
func New(cfg TransportConfig) auth.Transport {
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

// OnData sets callback for received messages.
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

// GetRegisteredOnData returns the current callback.
func (t *Transport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if t.messageCallback == nil {
		return nil, errors.New("no callback registered")
	}

	return t.messageCallback, nil
}

// Send writes an auth message via HTTP.
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

	case auth.MessageTypeGeneral:
		req, ok := ctx.Value(RequestKey).(*http.Request)
		if !ok {
			return errors.New("invalid request type in context")
		}

		requestID := ""
		if req != nil {
			requestID = req.Header.Get(constants.HeaderRequestID)
		}

		if requestID == "" {
			return errors.New("missing request ID for general message response")
		}

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

		if t.wallet != nil {
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
				Data: message.Payload,
			}

			signResult, err := t.wallet.CreateSignature(ctx, signatureArgs, "")
			if err != nil {
				return fmt.Errorf("failed to sign response payload: %w", err)
			}

			resp.Header().Set(constants.HeaderSignature, hex.EncodeToString(signResult.Signature.Serialize()))
		}

		return nil

	case auth.MessageTypeCertificateRequest, auth.MessageTypeInitialRequest:
		return fmt.Errorf("message type %s is not supported in Send method", message.MessageType)

	default:
		return fmt.Errorf("unsupported message type: %s", message.MessageType)
	}
}

// AuthMessageWithRequestID wraps auth.AuthMessage with a request ID.
type AuthMessageWithRequestID struct {
	*auth.AuthMessage
	RequestID string
}

// ParseAuthMessageFromRequest parses auth message from HTTP request.
func ParseAuthMessageFromRequest(req *http.Request) (*AuthMessageWithRequestID, error) {
	if req.URL.Path == constants.WellKnownAuthPath && req.Method == http.MethodPost {
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
		msg := &AuthMessageWithRequestID{
			AuthMessage: &message,
			RequestID:   req.Header.Get(constants.HeaderRequestID),
		}
		return msg, nil
	}

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
		sigBytes, err := hex.DecodeString(signature)
		if err != nil {
			return nil, fmt.Errorf("invalid signature format: %w", err)
		}

		message.Signature = sigBytes
	}
	msg := &AuthMessageWithRequestID{
		AuthMessage: message,
		RequestID:   requestID,
	}
	return msg, nil
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

	var includedHeaders [][]string
	for k, v := range req.Header {
		if isIncludedHeader(k) {
			includedHeaders = append(includedHeaders, []string{strings.ToLower(k), v[0]})
		}
	}
	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i][0] < includedHeaders[j][0]
	})

	writer.WriteVarInt(uint64(len(includedHeaders)))

	for _, header := range includedHeaders {
		writer.WriteString(header[0])
		writer.WriteString(header[1])
	}

	body, err := bodyContent(req)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	writer.WriteIntBytesOptional(body)

	return writer.Buf, nil
}

func isIncludedHeader(headerKey string) bool {
	k := strings.ToLower(headerKey)
	return (strings.HasPrefix(k, constants.XBSVPrefix) || k == constants.HeaderContentType || k == constants.HeaderAuthorization) &&
		!strings.HasPrefix(k, constants.AuthHeaderPrefix)
}

func bodyContent(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Create new reader for subsequent reads
	req.Body = io.NopCloser(strings.NewReader(string(body)))

	return body, nil
}
