package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
)

// contextKey is used for storing request/response in context
type contextKey string

const (
	// Context keys
	requestKey  contextKey = "http_request"
	responseKey contextKey = "http_response"
	nextKey     contextKey = "http_next_handler"

	// HTTP headers - as specified in BRC-104
	authHeaderPrefix  = "x-bsv-auth-"
	versionHeader     = authHeaderPrefix + "version"
	messageTypeHeader = authHeaderPrefix + "message-type"
	identityKeyHeader = authHeaderPrefix + "identity-key"
	nonceHeader       = authHeaderPrefix + "nonce"
	yourNonceHeader   = authHeaderPrefix + "your-nonce"
	signatureHeader   = authHeaderPrefix + "signature"
	requestIDHeader   = authHeaderPrefix + "request-id"
)

// ResponseRecorder wraps an http.ResponseWriter to track if a response has been written
type ResponseRecorder struct {
	http.ResponseWriter
	written    bool
	statusCode int
}

// WriteHeader records the status code and marks the response as written
func (r *ResponseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
	r.written = true
}

// Write records that the response has been written to
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}

// hasBeenWritten returns whether the response has been written to
func (r *ResponseRecorder) hasBeenWritten() bool {
	return r.written
}

func WrapResponseWriter(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// Transport implements the HTTP transport for BRC authentication
type Transport struct {
	wallet               wallet.AuthOperations
	sessionManager       auth.SessionManager
	allowUnauthenticated bool
	logger               *slog.Logger
	messageCallback      func(context.Context, *auth.AuthMessage) error
}

// New creates a new HTTP transport
func New(
	wallet wallet.AuthOperations,
	sessionManager auth.SessionManager,
	allowUnauthenticated bool,
	logger *slog.Logger,
) auth.Transport {
	transportLogger := logging.Child(logger, "http-transport")
	transportLogger.Info(fmt.Sprintf("Creating HTTP transport with allowUnauthenticated = %t", allowUnauthenticated))

	return &Transport{
		wallet:               wallet,
		sessionManager:       sessionManager,
		allowUnauthenticated: allowUnauthenticated,
		logger:               transportLogger,
	}
}

// OnData registers a callback for incoming auth messages
func (t *Transport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	if callback == nil {
		return errors.New("callback cannot be nil")
	}

	t.messageCallback = callback
	t.logger.Debug("Registered OnData callback")
	return nil
}

// GetRegisteredOnData returns the currently registered data handler
func (t *Transport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if t.messageCallback == nil {
		return nil, errors.New("no callback registered")
	}

	return t.messageCallback, nil
}

// Send handles sending auth messages through HTTP
func (t *Transport) Send(ctx context.Context, message *auth.AuthMessage) error {
	respVal := ctx.Value(responseKey)
	if respVal == nil {
		return errors.New("response writer not found in context")
	}

	resp, ok := respVal.(http.ResponseWriter)
	if !ok {
		return errors.New("invalid response writer type in context")
	}

	nextVal := ctx.Value(nextKey)
	var next func()
	if nextVal != nil {
		next, ok = nextVal.(func())
		if !ok {
			t.logger.Warn("Next handler has invalid type in context")
		}
	}

	if message.MessageType == auth.MessageTypeInitialResponse ||
		message.MessageType == auth.MessageTypeCertificateResponse {
		resp.Header().Set(versionHeader, message.Version)
		resp.Header().Set(messageTypeHeader, string(message.MessageType))
		resp.Header().Set(identityKeyHeader, message.IdentityKey.ToDERHex())

		if message.Nonce != "" {
			resp.Header().Set(nonceHeader, message.Nonce)
		}

		if message.YourNonce != "" {
			resp.Header().Set(yourNonceHeader, message.YourNonce)
		}

		if message.Signature != nil {
			resp.Header().Set(signatureHeader, hex.EncodeToString(message.Signature))
		}

		resp.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(resp).Encode(message); err != nil {
			return fmt.Errorf("failed to encode response message: %w", err)
		}

	} else if message.MessageType == auth.MessageTypeGeneral {
		req, _ := ctx.Value(requestKey).(*http.Request)
		requestID := ""
		if req != nil {
			requestID = req.Header.Get(requestIDHeader)
		}

		resp.Header().Set(versionHeader, message.Version)
		resp.Header().Set(identityKeyHeader, message.IdentityKey.ToDERHex())

		if message.Nonce != "" {
			resp.Header().Set(nonceHeader, message.Nonce)
		}

		if message.YourNonce != "" {
			resp.Header().Set(yourNonceHeader, message.YourNonce)
		}

		if message.Signature != nil {
			resp.Header().Set(signatureHeader, hex.EncodeToString(message.Signature))
		}

		if requestID != "" {
			resp.Header().Set(requestIDHeader, requestID)
		}

		if next != nil {
			next()
		}
	}

	return nil
}

// ParseAuthMessageFromRequest extracts an auth message from an HTTP request
func ParseAuthMessageFromRequest(req *http.Request) (*auth.AuthMessage, error) {
	if req.URL.Path == "/.well-known/auth" && req.Method == http.MethodPost {
		var message auth.AuthMessage
		if err := json.NewDecoder(req.Body).Decode(&message); err != nil {
			return nil, fmt.Errorf("invalid request body: %w", err)
		}

		return &message, nil

	} else {
		version := req.Header.Get(versionHeader)
		if version == "" {
			return nil, nil
		}

		identityKey := req.Header.Get(identityKeyHeader)
		if identityKey == "" {
			return nil, errors.New("missing identity key header")
		}

		nonce := req.Header.Get(nonceHeader)
		yourNonce := req.Header.Get(yourNonceHeader)
		signature := req.Header.Get(signatureHeader)
		requestID := req.Header.Get(requestIDHeader)

		pubKey, err := ec.PublicKeyFromString(identityKey)
		if err != nil {
			return nil, fmt.Errorf("invalid identity key format: %w", err)
		}

		payload, err := BuildRequestPayload(req, requestID)
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

		return message, nil
	}
}

// BuildRequestPayload creates a payload byte array from the request
func BuildRequestPayload(req *http.Request, requestID string) ([]byte, error) {
	writer := new(bytes.Buffer)

	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return nil, fmt.Errorf("invalid request ID format: %w", err)
	}
	writer.Write(requestIDBytes)

	methodLen := len(req.Method)
	err = WriteVarInt(writer, methodLen)
	if err != nil {
		return nil, fmt.Errorf("failed to write method length: %w", err)
	}

	writer.WriteString(req.Method)

	path := req.URL.Path
	if path == "" {
		err = WriteVarInt(writer, -1)
		if err != nil {
			return nil, fmt.Errorf("failed to write path length: %w", err)
		}
	} else {
		err = WriteVarInt(writer, len(path))
		if err != nil {
			return nil, fmt.Errorf("failed to write path length: %w", err)
		}

		writer.WriteString(path)
	}

	query := req.URL.RawQuery
	if query == "" {
		err = WriteVarInt(writer, -1)
		if err != nil {
			return nil, fmt.Errorf("failed to write query length: %w", err)
		}
	} else {
		err = WriteVarInt(writer, len(query))
		if err != nil {
			return nil, fmt.Errorf("failed to write query length: %w", err)
		}

		writer.WriteString(query)
	}

	var includedHeaders [][]string
	for k, v := range req.Header {
		k = strings.ToLower(k)
		if (strings.HasPrefix(k, "x-bsv-") || k == "content-type" || k == "authorization") &&
			!strings.HasPrefix(k, "x-bsv-auth") {
			includedHeaders = append(includedHeaders, []string{k, v[0]})
		}
	}

	// BRC-104 requires headers to be sorted lexicographically
	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i][0] < includedHeaders[j][0]
	})

	err = WriteVarInt(writer, len(includedHeaders))
	if err != nil {
		return nil, fmt.Errorf("failed to write headers length: %w", err)
	}
	for _, header := range includedHeaders {
		err = WriteVarInt(writer, len(header[0]))
		if err != nil {
			return nil, fmt.Errorf("failed to write header key length: %w", err)
		}

		writer.WriteString(header[0])
		err = WriteVarInt(writer, len(header[1]))
		if err != nil {
			return nil, fmt.Errorf("failed to write header value length: %w", err)
		}

		writer.WriteString(header[1])
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewBuffer(body))

		if len(body) > 0 {
			err = WriteVarInt(writer, len(body))
			if err != nil {
				return nil, fmt.Errorf("failed to write body length: %w", err)
			}

			writer.Write(body)
		} else {
			err = WriteVarInt(writer, -1)
			if err != nil {
				return nil, fmt.Errorf("failed to write body length: %w", err)
			}
		}
	} else {
		err = WriteVarInt(writer, -1)
		if err != nil {
			return nil, fmt.Errorf("failed to write body length: %w", err)
		}
	}

	return writer.Bytes(), nil
}

// WriteVarInt writes a variable integer to a buffer
// Used for creating BRC-104 compatible payloads
func WriteVarInt(w *bytes.Buffer, n int) error {
	return binary.Write(w, binary.LittleEndian, int64(n))
}

// HasBeenWritten checks if a response writer has written a response
func HasBeenWritten(w http.ResponseWriter) bool {
	if rw, ok := w.(*ResponseRecorder); ok {
		return rw.hasBeenWritten()
	}

	return false
}
