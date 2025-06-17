package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/util"
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
			errMsg := "Internal server error"

			switch {
			case errors.Is(err, auth.ErrNotAuthenticated):
				statusCode = http.StatusUnauthorized
				errMsg = "Authentication failed"
			case errors.Is(err, auth.ErrMissingCertificate):
				statusCode = http.StatusBadRequest
				var certTypes sdkUtils.RequestedCertificateTypeIDAndFieldList
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
			}

			http.Error(w, errMsg, statusCode)
			return
		}

		if authMsg.MessageType == auth.MessageTypeGeneral {

			signaturePayload, err := serializeRequest(r.Method, r.Header, authMsg.Payload, r.URL, []byte(authMsg.Nonce))
			if err != nil {
				m.logger.Error("Failed to serialize request", slog.String("error", err.Error()))
				http.Error(w, "Failed to serialize request", http.StatusInternalServerError)
				return
			}

			m.peer.ToPeer(ctx, signaturePayload, authMsg.IdentityKey, 30000)
		}

		if err := wrappedWriter.Flush(); err != nil {
			m.logger.Error("Failed to flush auth response", slog.String("error", err.Error()))
		}
		return
	})
}

func serializeRequest(method string, headers map[string][]string, body []byte, parsedURL *url.URL, requestNonce []byte) ([]byte, error) {
	writer := util.NewWriter()

	writer.WriteBytes(requestNonce)

	writer.WriteVarInt(uint64(len(method)))
	writer.WriteBytes([]byte(method))

	if parsedURL.Path != "" {
		pathBytes := []byte(parsedURL.Path)
		writer.WriteVarInt(uint64(len(pathBytes)))
		writer.WriteBytes(pathBytes)
	} else {
		writer.WriteVarInt(math.MaxUint64)
	}

	if parsedURL.RawQuery != "" {
		searchString := "?" + parsedURL.RawQuery
		searchBytes := []byte(searchString)
		writer.WriteVarInt(uint64(len(searchBytes)))
		writer.WriteBytes(searchBytes)
	} else {
		writer.WriteVarInt(math.MaxUint64)
	}

	var includedHeaders [][]string

	for key, values := range headers {
		headerKey := strings.ToLower(key)

		for _, value := range values {
			if strings.HasPrefix(headerKey, "x-bsv-") {
				if strings.HasPrefix(headerKey, "x-bsv-auth-") {
					continue
				}
				includedHeaders = append(includedHeaders, []string{headerKey, value})
			} else if headerKey == "authorization" {
				includedHeaders = append(includedHeaders, []string{headerKey, value})
			} else if strings.HasPrefix(headerKey, "content-type") {
				contentType := strings.Split(value, ";")[0]
				includedHeaders = append(includedHeaders, []string{headerKey, strings.TrimSpace(contentType)})
			}
		}
	}
	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i][0] < includedHeaders[j][0]
	})

	writer.WriteVarInt(uint64(len(includedHeaders)))

	for _, header := range includedHeaders {
		headerKey := header[0]
		headerKeyBytes := []byte(headerKey)
		writer.WriteVarInt(uint64(len(headerKeyBytes)))
		writer.WriteBytes(headerKeyBytes)

		headerValue := header[1]
		headerValueBytes := []byte(headerValue)
		writer.WriteVarInt(uint64(len(headerValueBytes)))
		writer.WriteBytes(headerValueBytes)
	}

	methodsThatTypicallyHaveBody := []string{"POST", "PUT", "PATCH", "DELETE"}
	if len(body) == 0 && contains(methodsThatTypicallyHaveBody, strings.ToUpper(method)) {
		for _, header := range includedHeaders {
			if header[0] == "content-type" && strings.Contains(header[1], "application/json") {
				body = []byte("{}")
				break
			}
		}

		if len(body) == 0 {
			body = []byte("")
		}
	}

	if len(body) > 0 {
		writer.WriteVarInt(uint64(len(body)))
		writer.WriteBytes(body)
	} else {
		writer.WriteVarInt(math.MaxUint64)
	}

	return writer.Buf, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// prepareMissingCertificateTypesErrorMsg prepares a user-friendly error message for missing certificate types.
func prepareMissingCertificateTypesErrorMsg(missingCertTypes sdkUtils.RequestedCertificateTypeIDAndFieldList) string {
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
