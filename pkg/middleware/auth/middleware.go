package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/util"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
)

// Middleware is an HTTP middleware that handles authentication messages.
type Middleware struct {
	wallet               interfaces.Wallet
	peer                 *auth.Peer
	sessionManager       auth.SessionManager
	transport            auth.Transport
	allowUnauthenticated bool
	logger               *slog.Logger
}

// New creates a new instance of the auth middleware.
func New(cfg Config) (*Middleware, error) {
	if cfg.Wallet == nil {
		return nil, errors.New("wallet is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	middlewareLogger := logging.Child(logger, "auth-middleware")

	sessionManager := cfg.SessionManager
	if sessionManager == nil {
		sessionManager = auth.NewSessionManager()
	}

	if cfg.OnCertificatesReceived == nil && cfg.CertificatesToRequest != nil {
		return nil, errors.New("OnCertificatesReceived callback is required when certificates are requested")
	}

	if cfg.OnCertificatesReceived != nil && cfg.CertificatesToRequest == nil {
		return nil, errors.New("OnCertificatesReceived callback is set but no certificates are requested")
	}

	transportCfg := httptransport.TransportConfig{
		Wallet:                 cfg.Wallet,
		SessionManager:         sessionManager,
		Logger:                 logger,
		CertificatesToRequest:  cfg.CertificatesToRequest,
		OnCertificatesReceived: cfg.OnCertificatesReceived,
	}

	t := httptransport.New(transportCfg)

	peerCfg := &auth.PeerOptions{
		Wallet:                cfg.Wallet,
		Transport:             t,
		SessionManager:        sessionManager,
		CertificatesToRequest: cfg.CertificatesToRequest,
	}
	peer := auth.NewPeer(peerCfg)
	peer.ListenForCertificatesReceived(cfg.OnCertificatesReceived)

	return &Middleware{
		peer:                 peer,
		wallet:               cfg.Wallet,
		sessionManager:       sessionManager,
		transport:            t,
		allowUnauthenticated: cfg.AllowUnauthenticated,
		logger:               middlewareLogger,
	}, nil
}

// Handler returns an HTTP handler that processes incoming requests and handles authentication messages.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrappedWriter := httptransport.WrapResponseWriter(w)

		ctx := context.WithValue(r.Context(), httptransport.RequestKey, r)
		ctx = context.WithValue(ctx, httptransport.ResponseKey, wrappedWriter)
		ctx = context.WithValue(ctx, httptransport.NextKey, func() {
			next.ServeHTTP(wrappedWriter, r)
		})

		m.logger.Debug("Processing request",
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method))

		authMsg, err := httptransport.ParseAuthMessageFromRequest(r)
		if err != nil {
			m.logger.Error("Failed to parse auth message", slog.String("error", err.Error()))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if authMsg == nil {
			if m.allowUnauthenticated {
				r = r.WithContext(context.WithValue(r.Context(), httptransport.IdentityKey, constants.UnknownParty))
				next.ServeHTTP(w, r)
				return
			} else {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}
		}

		if authMsg.IdentityKey == nil {
			m.logger.Error("Internal error: ParseAuthMessageFromRequest returned message with nil IdentityKey")
			http.Error(w, "Internal authentication error", http.StatusInternalServerError)
			return
		}

		callback, err := m.transport.GetRegisteredOnData()
		if err != nil {
			m.logger.Error("No message handler registered", slog.String("error", err.Error()))
			http.Error(w, "Server configuration error", http.StatusInternalServerError)
			return
		}

		if err := callback(ctx, authMsg.AuthMessage); err != nil {
			m.logger.Error("Failed to process auth message", slog.String("error", err.Error()))

			statusCode := http.StatusInternalServerError
			// Ensure we handle the error correctly
			errMsg := "Internal server error"
			// errors.Join(err, errMsg)
			// To handle errors more gracefully, we need go-sdk to return specific error types
			// For now majority of errors will be treated as internal server error

			switch {
			case errors.Is(err, auth.ErrNotAuthenticated):
				statusCode = http.StatusUnauthorized
				errMsg = "Authentication failed"
			case errors.Is(err, auth.ErrMissingCertificate):
				statusCode = http.StatusBadRequest
				var certTypes utils.RequestedCertificateTypeIDAndFieldList
				if m.peer != nil && m.peer.CertificatesToRequest != nil {
					certTypes = m.peer.CertificatesToRequest.CertificateTypes
				}
				errMsg = prepareMissingCertificateTypesErrorMsg(certTypes)
			case errors.Is(err, auth.ErrInvalidNonce):
				statusCode = http.StatusBadRequest
				errMsg = "Invalid nonce"
			case errors.Is(err, auth.ErrInvalidMessage):
				statusCode = http.StatusBadRequest
				errMsg = "Invalid message format"
			case errors.Is(err, auth.ErrSessionNotFound):
				statusCode = http.StatusUnauthorized
				errMsg = "Session not found"
			default:
				// errMsg = errMsg + err.Error()
				errMsg = fmt.Sprintf("%s: %s", errMsg, err.Error())
			}

			http.Error(w, errMsg, statusCode)
			return
		}

		if authMsg.MessageType == auth.MessageTypeGeneral {
			next.ServeHTTP(wrappedWriter, r)

			statusCode := wrappedWriter.GetStatusCode()
			responseBody := wrappedWriter.GetBody()
			responseHeaders := wrappedWriter.Header()

			createRequestPayload, err := buildResponsePayload(authMsg.RequestID, statusCode, responseHeaders, responseBody)
			if err != nil {
				m.logger.Error("Failed to create request payload", slog.String("error", err.Error()))
				http.Error(w, "Failed to create request payload", http.StatusInternalServerError)
				return
			}

			err = m.peer.ToPeer(ctx, createRequestPayload, authMsg.IdentityKey, 30000)
			if err != nil {
				m.logger.Error("Failed to send request to peer", slog.String("error", err.Error()), slog.String("identityKey", authMsg.IdentityKey.ToDERHex()))
				http.Error(w, "Failed to send request to peer", http.StatusInternalServerError)
				return
			}
		}

		if err := wrappedWriter.Flush(); err != nil {
			m.logger.Error("Failed to flush auth response", slog.String("error", err.Error()))
		}
		return
	})
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

type headerPair struct {
	Key   string
	Value string
}

// buildResponsePayload creates a BRC-103 response payload according to BRC-104 section 6.9
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
	writer.WriteVarInt(uint64(statusCode))
	includedHeaders := filterAndSortResponseHeaders(headers)
	writer.WriteVarInt(uint64(len(includedHeaders)))
	for _, header := range includedHeaders {
		keyBytes := []byte(header[0])
		writer.WriteVarInt(uint64(len(keyBytes)))
		writer.WriteBytes(keyBytes)
		valueBytes := []byte(header[1])
		writer.WriteVarInt(uint64(len(valueBytes)))
		writer.WriteBytes(valueBytes)
	}
	if len(body) > 0 {
		writer.WriteVarInt(uint64(len(body)))
		writer.WriteBytes(body)
	} else {
		writer.WriteVarInt(uint64(^uint64(0)))
	}
	return writer.Buf, nil
}

func getWhitelistedHeaders(headers http.Header, isRequest bool) []headerPair {
	var result []headerPair

	for key, values := range headers {
		lowerKey := strings.ToLower(key)

		if strings.HasPrefix(lowerKey, constants.AuthHeaderPrefix) {
			continue
		}

		if lowerKey == constants.HeaderAuthorization {
			for _, value := range values {
				result = append(result, headerPair{Key: lowerKey, Value: value})
			}
		} else if isRequest && lowerKey == constants.HeaderContentType {
			for _, value := range values {
				contentType := strings.Split(value, ";")[0]
				result = append(result, headerPair{Key: lowerKey, Value: strings.TrimSpace(contentType)})
			}
		} else if strings.HasPrefix(lowerKey, constants.XBSVPrefix) {
			for _, value := range values {
				result = append(result, headerPair{Key: lowerKey, Value: value})
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Key < result[j].Key
	})

	return result
}

// filterAndSortResponseHeaders filters response headers according to BRC-104 rules
// Only includes headers with x-bsv- prefix (excluding x-bsv-auth-*) and authorization header
func filterAndSortResponseHeaders(headers http.Header) [][2]string {
	var includedHeaders [][2]string
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		if (strings.HasPrefix(lowerKey, constants.XBSVPrefix) && !strings.HasPrefix(lowerKey, constants.AuthHeaderPrefix)) ||
			lowerKey == constants.HeaderAuthorization {
			for _, value := range values {
				includedHeaders = append(includedHeaders, [2]string{lowerKey, value})
			}
		}
	}
	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i][0] < includedHeaders[j][0]
	})

	return includedHeaders
}
