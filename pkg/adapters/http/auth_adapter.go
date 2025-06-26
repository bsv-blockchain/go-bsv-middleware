package httpadapter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	internaltransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/transport"
	authmiddleware "github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/util"
)

// HTTPAuthMiddleware connects HTTP requests to transport-agnostic middleware
type HTTPAuthMiddleware struct {
	middleware *authmiddleware.Middleware
	logger     *slog.Logger
}

// NewHTTPAuthMiddleware creates an adapter for HTTP authentication middleware
func NewHTTPAuthMiddleware(config authmiddleware.Config, logger *slog.Logger) *HTTPAuthMiddleware {

	middleware, err := authmiddleware.New(config)
	if err != nil {
		logger.Error("Failed to create auth middleware", slog.String("error", err.Error()))
		return nil
	}

	return &HTTPAuthMiddleware{
		middleware: middleware,
		logger:     logger,
	}
}

func (a *HTTPAuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.logger.Debug("Processing HTTP request",
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method))

		authMsg, ctx, err := a.parseHTTPRequest(w, r, next)
		if err != nil {
			a.handleHTTPError(w, err)
			return
		}

		if err := a.middleware.ProcessAuthentication(ctx, authMsg); err != nil {
			a.handleHTTPError(w, err)
			return
		}

		// if authMsg != nil && r.Header.Get("x-bsv-auth-request-id") != "" {
		// 	err := a.addBRC104ResponseHeaders(w, r, authMsg)
		// 	if err != nil {
		// 		a.logger.Error("Failed to add BRC-104 response headers", slog.String("error", err.Error()))
		// 		// Don't fail the request, just log the error
		// 	}
		// }
		// // ADD THIS: Check if this should be auto-handled

		if authMsg != nil && r.Header.Get("x-bsv-auth-request-id") != "" {
			// Authentication successful - now respond to the client using ToPeer
			err := a.sendPeerResponse(ctx, w, r, authMsg)
			if err != nil {
				a.logger.Error("Failed to send peer response", slog.String("error", err.Error()))
				a.handleHTTPError(w, err)
				return
			}
			return // Don't call next.ServeHTTP for auto-handled auth requests
		}

		if a.shouldAutoRespond(r, authMsg) {
			a.logger.Debug("Auto-responding to auth endpoint")
			a.handleAutoResponse(w, r, authMsg)
			return
		}

		var identity string
		if authMsg != nil {
			identity = authMsg.IdentityKey.ToDERHex()
		} else {
			identity = constants.UnknownParty
		}

		enrichedCtx := context.WithValue(ctx, httptransport.IdentityKey, identity)
		r = r.WithContext(enrichedCtx)
		next.ServeHTTP(w, r)
	})
}

// shouldAutoRespond determines if middleware should auto-respond
func (a *HTTPAuthMiddleware) shouldAutoRespond(r *http.Request, authMsg *auth.AuthMessage) bool {
	// Auto-respond to well-known auth endpoint
	if r.URL.Path == constants.WellKnownAuthPath && r.Method == http.MethodPost {
		return true
	}

	// Auto-respond to general auth requests
	if authMsg != nil && a.isGeneralAuthRequest(r) {
		return true
	}

	return false
}

// isGeneralAuthRequest checks if this is a general auth request
func (a *HTTPAuthMiddleware) isGeneralAuthRequest(r *http.Request) bool {
	return r.Header.Get(constants.HeaderRequestID) != "" &&
		r.Header.Get(constants.HeaderIdentityKey) != "" &&
		r.Header.Get(constants.HeaderVersion) != ""
}

// handleAutoResponse handles automatic responses for auth endpoints
func (a *HTTPAuthMiddleware) handleAutoResponse(w http.ResponseWriter, r *http.Request, authMsg *auth.AuthMessage) {
	if r.URL.Path == constants.WellKnownAuthPath {
		a.handleWellKnownAuthResponse(w, r, authMsg)
	} else {
		a.handleGeneralAuthResponse(w, r, authMsg)
	}
}

// handleWellKnownAuthResponse handles well-known auth responses
func (a *HTTPAuthMiddleware) handleWellKnownAuthResponse(w http.ResponseWriter, r *http.Request, authMsg *auth.AuthMessage) {
	a.logger.Debug("Handling well-known auth response via transport",
		slog.String("messageType", string(authMsg.MessageType)))

	// Get the transport layer to handle response generation
	transport := a.middleware.GetTransport()
	if transport == nil {
		a.logger.Error("No transport available for response generation")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Transport not available"}`))
		return
	}

	// Set up context with response writer for transport layer
	ctx := context.WithValue(r.Context(), httptransport.ResponseKey, w)
	ctx = context.WithValue(ctx, httptransport.RequestKey, r)

	// Get the registered callback from transport
	callback, err := transport.GetRegisteredOnData()
	if err != nil {
		a.logger.Error("No callback registered on transport", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"No auth callback registered"}`))
		return
	}

	// Call the callback to process the message and generate response
	if err := callback(ctx, authMsg); err != nil {
		a.logger.Error("Failed to process auth message via transport", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to process authentication"}`))
		return
	}

	a.logger.Debug("Well-known auth response handled successfully")
}

// handleGeneralAuthResponse handles general auth responses
func (a *HTTPAuthMiddleware) handleGeneralAuthResponse(w http.ResponseWriter, r *http.Request, authMsg *auth.AuthMessage) {
	a.logger.Debug("Auto-responding to general auth request",
		slog.String("path", r.URL.Path),
		slog.String("identity", authMsg.IdentityKey.ToDERHex()))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":        "success",
		"authenticated": true,
		"message":       "General authentication successful",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		a.logger.Error("Failed to encode response", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// // Handler returns an HTTP handler
// func (a *HTTPAuthMiddleware) Handler(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		a.logger.Debug("Processing HTTP request",
// 			slog.String("path", r.URL.Path),
// 			slog.String("method", r.Method))

// 		authMsg, ctx, err := a.parseHTTPRequest(w, r, next)
// 		if err != nil {
// 			a.handleHTTPError(w, err)
// 			return
// 		}

// 		if err := a.middleware.ProcessAuthentication(ctx, authMsg); err != nil {
// 			a.handleHTTPError(w, err)
// 			return
// 		}

// 		var identity string
// 		if authMsg != nil {
// 			identity = authMsg.IdentityKey.ToDERHex()
// 		} else {
// 			identity = constants.UnknownParty
// 		}

// 		enrichedCtx := context.WithValue(ctx, httptransport.IdentityKey, identity)
// 		r = r.WithContext(enrichedCtx)
// 		next.ServeHTTP(w, r)
// 	})
// }

func (a *HTTPAuthMiddleware) parseHTTPRequest(w http.ResponseWriter, r *http.Request, next http.Handler) (*auth.AuthMessage, context.Context, error) {
	a.logger.Debug("parseHTTPRequest entry",
		slog.String("path", r.URL.Path),
		slog.String("method", r.Method))

	isAuthEndpoint := a.isAuthEndpoint(r)
	a.logger.Debug("isAuthEndpoint check",
		slog.Bool("isAuthEndpoint", isAuthEndpoint),
		slog.String("requestID", r.Header.Get(constants.HeaderRequestID)),
		slog.String("identityKey", r.Header.Get(constants.HeaderIdentityKey)))

	wrappedWriter := internaltransport.WrapResponseWriter(w)
	ctx := context.WithValue(r.Context(), httptransport.RequestKey, r)
	ctx = context.WithValue(ctx, httptransport.ResponseKey, wrappedWriter)

	if !isAuthEndpoint {
		a.logger.Debug("Setting NextKey for non-auth endpoint")
		ctx = context.WithValue(ctx, httptransport.NextKey, func() {
			a.logger.Debug("Calling next.ServeHTTP", slog.String("path", r.URL.Path))
			next.ServeHTTP(wrappedWriter, r)
		})
	} else {
		a.logger.Debug("Skipping NextKey for auth endpoint")
	}

	authMsgWithID, err := httptransport.ParseAuthMessageFromRequest(r)
	a.logger.Debug("ParseAuthMessageFromRequest result",
		slog.Bool("authMsgIsNil", authMsgWithID == nil),
		slog.Any("error", err))

	if err != nil {
		a.logger.Error("Failed to parse auth message", slog.String("error", err.Error()))
		return nil, ctx, errors.New("failed to parse authentication message")
	}

	if authMsgWithID == nil {
		a.logger.Debug("No auth message found, returning nil")
		return nil, ctx, nil
	}

	if authMsgWithID.IdentityKey == nil {
		a.logger.Error("Missing identity key in auth message")
		return nil, ctx, errors.New("internal authentication error")
	}

	a.logger.Debug("Returning auth message",
		slog.String("identityKey", authMsgWithID.IdentityKey.ToDERHex()))
	return authMsgWithID.AuthMessage, ctx, nil
}

// handleHTTPError converts errors to HTTP responses (transport-specific)
func (a *HTTPAuthMiddleware) handleHTTPError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	errMsg := "Internal server error"

	switch {
	case errors.Is(err, auth.ErrNotAuthenticated):
		statusCode = http.StatusUnauthorized
		errMsg = "Authentication failed"
	case errors.Is(err, auth.ErrMissingCertificate):
		statusCode = http.StatusBadRequest
		var certTypes sdkUtils.RequestedCertificateTypeIDAndFieldList
		if peer := a.middleware.GetPeer(); peer != nil && peer.CertificatesToRequest != nil {
			certTypes = peer.CertificatesToRequest.CertificateTypes
		}
		errMsg = prepareMissingCertificateTypesErrorMsg(certTypes)
	case errors.Is(err, auth.ErrInvalidNonce):
		statusCode = http.StatusBadRequest
		errMsg = "Invalid nonce"
	case errors.Is(err, auth.ErrInvalidMessage):
		statusCode = http.StatusBadRequest
		errMsg = "Invalid message format"
	case err.Error() == "authentication required":
		statusCode = http.StatusUnauthorized
		errMsg = "Authentication required"
	case err.Error() == "server configuration error":
		statusCode = http.StatusInternalServerError
		errMsg = "Server configuration error"
	default:
		a.logger.Error("Unhandled auth error", slog.String("error", err.Error()))
	}

	http.Error(w, errMsg, statusCode)
}

// prepareMissingCertificateTypesErrorMsg creates error message for missing certificates
func prepareMissingCertificateTypesErrorMsg(certTypes sdkUtils.RequestedCertificateTypeIDAndFieldList) string {
	if len(certTypes) == 0 {
		return "Missing required certificates"
	}

	var sb strings.Builder
	sb.WriteString("Missing required certificates: ")
	first := true
	for certTypeID, requiredFields := range certTypes {
		if !first {
			sb.WriteString(", ")
		}
		first = false
		certTypeIDStr := base64.StdEncoding.EncodeToString(certTypeID[:])
		sb.WriteString(certTypeIDStr)
		if len(requiredFields) > 0 {
			sb.WriteString(" (fields: ")
			for j, field := range requiredFields {
				if j > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(field)
			}
			sb.WriteString(")")
		}
	}

	return sb.String()
}

func (a *HTTPAuthMiddleware) isAuthEndpoint(r *http.Request) bool {
	// Well-known auth endpoint - always auto-handle
	if r.URL.Path == constants.WellKnownAuthPath {
		a.logger.Debug("Identified as well-known auth endpoint")
		return true
	}

	// Check for general auth request headers
	hasRequestID := r.Header.Get(constants.HeaderRequestID) != ""
	hasIdentityKey := r.Header.Get(constants.HeaderIdentityKey) != ""
	hasVersion := r.Header.Get(constants.HeaderVersion) != ""

	a.logger.Debug("General auth header check",
		slog.Bool("hasRequestID", hasRequestID),
		slog.Bool("hasIdentityKey", hasIdentityKey),
		slog.Bool("hasVersion", hasVersion),
		slog.String("path", r.URL.Path),
		slog.String("requestID", r.Header.Get(constants.HeaderRequestID)),
		slog.String("identityKey", r.Header.Get(constants.HeaderIdentityKey)))

	// CORRECTED LOGIC: If it has BSV auth headers, it's a general auth request
	// that should be auto-handled regardless of path
	if hasRequestID && hasIdentityKey && hasVersion {
		a.logger.Debug("Identified as general auth endpoint - has required BSV headers")
		return true
	}

	return false
}

// func (a *HTTPAuthMiddleware) sendPeerResponse(ctx context.Context, w http.ResponseWriter, r *http.Request, authMsg *auth.AuthMessage) error {
// 	peer := a.middleware.GetPeer()
// 	if peer == nil {
// 		return errors.New("peer not available")
// 	}

// 	// Create a response payload that includes the HTTP response
// 	// For now, create a simple success response
// 	responseData := map[string]interface{}{
// 		"status":        "success",
// 		"authenticated": true,
// 		"message":       "Request processed successfully",
// 	}

// 	responseBytes, err := json.Marshal(responseData)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal response: %w", err)
// 	}

// 	// Build the BRC-104 response payload (requestId + status + headers + body)
// 	requestID := r.Header.Get("x-bsv-auth-request-id")
// 	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
// 	if err != nil {
// 		return fmt.Errorf("invalid request ID: %w", err)
// 	}

// 	writer := util.NewWriter()

// 	// Write request ID (echoing back)
// 	writer.WriteBytes(requestIDBytes)

// 	// Write status code
// 	writer.WriteVarInt(uint64(200)) // HTTP 200 OK

// 	// Write headers (empty for now, but could include custom headers)
// 	writer.WriteVarInt(uint64(0)) // No additional headers

// 	// Write response body
// 	writer.WriteVarInt(uint64(len(responseBytes)))
// 	writer.WriteBytes(responseBytes)

// 	responsePayload := writer.Buf

// 	// Use ToPeer to send the response back to the client
// 	err = peer.ToPeer(ctx, responsePayload, authMsg.IdentityKey, 5000) // 5 second timeout
// 	if err != nil {
// 		return fmt.Errorf("failed to send response via ToPeer: %w", err)
// 	}

// 	a.logger.Debug("Successfully sent peer response via ToPeer")
// 	return nil
// }

func (a *HTTPAuthMiddleware) sendPeerResponse(ctx context.Context, w http.ResponseWriter, r *http.Request, authMsg *auth.AuthMessage) error {
	peer := a.middleware.GetPeer()
	if peer == nil {
		return errors.New("peer not available")
	}

	// For now, create a simple response that matches what the server originally sent
	// We'll send back the exact same request ID that the client sent
	requestID := r.Header.Get("x-bsv-auth-request-id")
	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return fmt.Errorf("invalid request ID: %w", err)
	}

	// Use only the request ID as the payload for now to match the expected format
	// responsePayload := requestIDBytes + byte(200)

	writer := util.NewWriter()
	writer.WriteBytes(requestIDBytes) // Write request ID
	writer.WriteVarInt(uint64(200))   // Write HTTP status code 200 OK
	writer.WriteVarInt(0)             // No additional headers
	writer.WriteVarInt(0)             // No body content

	responsePayload := writer.Buf

	a.logger.Debug("Sending peer response",
		slog.String("requestId", requestID),
		slog.Int("payloadLength", len(responsePayload)))

	// Use ToPeer to send the response back to the client
	err = peer.ToPeer(ctx, responsePayload, authMsg.IdentityKey, 5000) // 5 second timeout
	if err != nil {
		return fmt.Errorf("failed to send response via ToPeer: %w", err)
	}

	// Empty JSON response

	a.logger.Debug("Successfully sent peer response via ToPeer")
	return nil
}
