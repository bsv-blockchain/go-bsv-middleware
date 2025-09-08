package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
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

	middlewareLogger := logging.Child(cfg.Logger, "AuthMiddleware")

	sessionManager := cfg.SessionManager
	if sessionManager == nil {
		sessionManager = auth.NewSessionManager()
	}

	transportCfg := httptransport.TransportConfig{
		Wallet:                 cfg.Wallet,
		SessionManager:         sessionManager,
		Logger:                 middlewareLogger,
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

		ctx := r.Context()
		ctx = context.WithValue(ctx, httptransport.RequestKey, r)
		ctx = context.WithValue(ctx, httptransport.ResponseKey, wrappedWriter)
		r = r.WithContext(ctx)

		m.logger.DebugContext(ctx, "Processing request",
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
				m.logger.DebugContext(ctx, "Allowing unauthenticated request to pass through", slog.String("path", r.URL.Path), slog.String("method", r.Method))
				r = r.WithContext(context.WithValue(r.Context(), httptransport.IdentityKey, constants.UnknownParty))
				next.ServeHTTP(w, r)
				return
			} else {
				m.logger.WarnContext(ctx, "Rejecting unauthenticated request", slog.String("path", r.URL.Path), slog.String("method", r.Method))
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}
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
			case errors.Is(err, auth.ErrInvalidSignature):
				// TODO: change to Unauthorized respond with valid message so the ts could print it properly
				statusCode = http.StatusInternalServerError
				errMsg = "Invalid signature"
			default:
				errMsg = fmt.Sprintf("%s: %s", errMsg, err.Error())
			}

			acceptType := r.Header.Get("Accept")
			mediaType, _, err := mime.ParseMediaType(acceptType)
			if err != nil {
				m.logger.Error("Failed to parse Accept header value", slog.String("error", err.Error()))
			}

			var response string
			switch mediaType {
			case "text/plain":
				w.Header().Set("Content-Type", "text/plain")
				response = errMsg
			default:
				w.Header().Set("Content-Type", "application/json")
				response = fmt.Sprintf(`{"error":"%s"}`, errMsg)
			}
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(statusCode)
			_, err = w.Write([]byte(response))
			if err != nil {
				m.logger.Error("Failed to write error response", slog.String("error", err.Error()), slog.String("response", response))
			}
			return
		}

		if authMsg.MessageType == auth.MessageTypeGeneral {
			next.ServeHTTP(wrappedWriter, r)

			response := authpayload.SimplifiedHttpResponse{
				StatusCode: wrappedWriter.GetStatusCode(),
				Header:     wrappedWriter.Header(),
				Body:       wrappedWriter.GetBody(),
			}

			responsePayload, err := authpayload.FromResponse(authMsg.RequestIDBytes, response)
			if err != nil {
				m.logger.Error("Failed to create request payload", slog.String("error", err.Error()))
				http.Error(w, "Failed to create request payload", http.StatusInternalServerError)
				return
			}

			err = m.peer.ToPeer(ctx, responsePayload, authMsg.IdentityKey, 30000)
			if err != nil {
				m.logger.Error("Failed to send request to peer", slog.String("error", err.Error()), slog.String("identityKey", authMsg.IdentityKey.ToDERHex()))
				http.Error(w, "Failed to send request to peer", http.StatusInternalServerError)
				return
			}
		}

		if err := wrappedWriter.Flush(); err != nil {
			m.logger.Error("Failed to flush auth response", slog.String("error", err.Error()))
		}
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
