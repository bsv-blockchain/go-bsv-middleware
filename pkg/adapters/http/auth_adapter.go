package httpadapter

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	internaltransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/transport"
	authmiddleware "github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
)

// HTTPAuthAdapter connects HTTP requests to transport-agnostic middleware
type HTTPAuthAdapter struct {
	middleware *authmiddleware.Middleware
	logger     *slog.Logger
}

// NewHTTPAuthAdapter creates an adapter for HTTP authentication middleware
func NewHTTPAuthAdapter(middleware *authmiddleware.Middleware, logger *slog.Logger) *HTTPAuthAdapter {
	return &HTTPAuthAdapter{
		middleware: middleware,
		logger:     logger,
	}
}

// Handler returns an HTTP handler
func (a *HTTPAuthAdapter) Handler(next http.Handler) http.Handler {
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

// parseHTTPRequest handles ALL HTTP-specific parsing
func (a *HTTPAuthAdapter) parseHTTPRequest(w http.ResponseWriter, r *http.Request, next http.Handler) (*auth.AuthMessage, context.Context, error) {
	wrappedWriter := internaltransport.WrapResponseWriter(w)
	ctx := context.WithValue(r.Context(), httptransport.RequestKey, r)
	ctx = context.WithValue(ctx, httptransport.ResponseKey, wrappedWriter)
	ctx = context.WithValue(ctx, httptransport.NextKey, func() {
		next.ServeHTTP(wrappedWriter, r)
	})

	authMsgWithID, err := httptransport.ParseAuthMessageFromRequest(r)
	if err != nil {
		a.logger.Error("Failed to parse auth message", slog.String("error", err.Error()))
		return nil, ctx, errors.New("failed to parse authentication message")
	}

	if authMsgWithID == nil {
		return nil, ctx, nil
	}

	if authMsgWithID.IdentityKey == nil {
		a.logger.Error("Missing identity key in auth message")
		return nil, ctx, errors.New("internal authentication error")
	}

	return authMsgWithID.AuthMessage, ctx, nil
}

// handleHTTPError converts errors to HTTP responses (transport-specific)
func (a *HTTPAuthAdapter) handleHTTPError(w http.ResponseWriter, err error) {
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
