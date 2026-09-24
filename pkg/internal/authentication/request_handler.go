package authentication

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/go-softwarelab/common/pkg/slogx"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/authctx"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
)

const maxToPeerWaitTime = 30000

var (
	ErrInvalidNonGeneralRequest = fmt.Errorf("bad request")
	ErrInvalidGeneralRequest    = fmt.Errorf("invalid authentication")
	ErrProcessingMessageByPeer  = fmt.Errorf("error while processing message by peer")
	ErrAuthenticationRequired   = fmt.Errorf("authentication required")
	// ErrResponseSigningFailed is returned when the peer fails to sign and/or
	// deliver the authenticated response payload (e.g. the wallet's signing
	// operation errors), matching the TS reference's ERR_RESPONSE_SIGNING_FAILED.
	ErrResponseSigningFailed = fmt.Errorf("failed to sign authenticated response")
	// ErrCertificateTimeout is returned when a general request arrives on a
	// session whose required certificate exchange has not completed, and it
	// still hasn't completed by the time certificateWaitGate gives up.
	// Matching the TS reference's CERTIFICATE_TIMEOUT (auth-express-middleware's
	// ExpressTransport#scheduleNextOrCertificateWait).
	ErrCertificateTimeout = fmt.Errorf("certificate approval timed out")
)

type AuthRequestHandler interface {
	Handle(ctx context.Context, response http.ResponseWriter, request *http.Request) error
}

type NonGeneralRequestHandler struct {
	log                   *slog.Logger
	handleMessageWithPeer func(context.Context, *auth.AuthMessage) error
}

func (h *NonGeneralRequestHandler) Handle(ctx context.Context, _ http.ResponseWriter, request *http.Request) (err error) {
	log := h.log

	log.DebugContext(ctx, "handling non-general request")
	defer func() {
		if err != nil {
			log.WarnContext(ctx, "Failed to handle non-general request", slogx.Error(err))
		}
	}()

	authMessage, err := extractNonGeneralAuthMessage(h.log, request)
	if err != nil {
		return errors.Join(ErrInvalidNonGeneralRequest, err)
	}

	log = log.With(logging.AuthMessage(authMessage))

	log.DebugContext(ctx, "auth message extracted from request")

	if err := h.handleMessageWithPeer(ctx, authMessage); err != nil {
		return errors.Join(ErrProcessingMessageByPeer, err)
	}

	h.log.DebugContext(ctx, "message successfully processed with peer")

	return nil
}

type GeneralRequestHandler struct {
	log                   *slog.Logger
	handleMessageWithPeer func(context.Context, *auth.AuthMessage) error
	nextHandler           http.Handler
	peer                  *auth.Peer
	allowUnauthenticated  bool
	// certWaitGate is non-nil only when the server requires certificates and
	// registered Config.OnCertificatesReceived (see Middleware.NewMiddleware).
	// It is consulted only when handleMessageWithPeer reports
	// auth.ErrNotAuthenticated - see handleCertificateWait.
	certWaitGate *certificateWaitGate
}

func (h *GeneralRequestHandler) Handle(ctx context.Context, httpResponse http.ResponseWriter, request *http.Request) (err error) {
	log := h.log

	log.DebugContext(ctx, "Handling general request")
	defer func() {
		if err != nil {
			log.WarnContext(ctx, "Failed to handle request", slogx.Error(err))
		}
	}()

	authMessage, err := extractGeneralAuthMessage(request)
	if err != nil {
		if errors.Is(err, ErrAuthenticationRequired) {
			return h.handleUnauthenticated(ctx, httpResponse, request)
		}
		return errors.Join(ErrInvalidGeneralRequest, err)
	}

	ctx = authctx.WithIdentity(ctx, authMessage.IdentityKey)

	log = log.With(logging.RequestID(authMessage.RequestID), logging.AuthMessage(authMessage.AuthMessage))

	log.DebugContext(ctx, "Auth message extracted from request")

	if peerErr := h.processMessageWithCertificateWait(ctx, authMessage); peerErr != nil {
		return errors.Join(ErrProcessingMessageByPeer, peerErr)
	}
	h.log.DebugContext(ctx, "Message successfully processed with peer")

	h.log.DebugContext(ctx, "Passing request to next handler")

	response := WrapResponseWriter(httpResponse)

	ctx = authctx.WithResponse(ctx, response)
	request = request.WithContext(ctx)

	h.nextHandler.ServeHTTP(response, request)

	h.log.DebugContext(ctx, "Preparing payload from response for signing")
	responsePayload, err := authpayload.FromResponse(
		authMessage.RequestIDBytes,
		authpayload.SimplifiedHttpResponse{
			StatusCode: response.GetStatusCode(),
			Header:     response.Header(),
			Body:       response.GetBody(),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create response payload: %w", err)
	}

	h.log.DebugContext(ctx, "Sending response to peer")
	err = h.peer.ToPeer(ctx, responsePayload, authMessage.IdentityKey, maxToPeerWaitTime)
	if err != nil {
		return errors.Join(ErrResponseSigningFailed, err)
	}

	h.log.DebugContext(ctx, "Writing http response")
	err = response.Flush()
	if err != nil {
		h.log.Error("Failed to write http response", slogx.Error(err))
		// if this failed we can't do anything more about this error.
		return nil
	}

	return nil
}

// processMessageWithCertificateWait delivers authMessage to go-sdk's Peer,
// and - only when h.certWaitGate is configured (the server requires
// certificates and registered Config.OnCertificatesReceived) - holds a
// request that arrived before its session's certificate exchange completed
// open until that exchange finishes or the gate's timeout elapses, instead
// of failing it immediately. This mirrors the TS reference's
// ExpressTransport#scheduleNextOrCertificateWait (auth-express-middleware).
//
// go-sdk's Peer reports this specific situation as auth.ErrNotAuthenticated
// (see auth.Peer.handleGeneralMessage's `if !session.IsAuthenticated` check),
// which it returns before verifying the message's signature or claiming its
// nonce, so retrying with the very same authMessage once certificates are
// approved is safe: nothing about this delivery attempt was consumed.
func (h *GeneralRequestHandler) processMessageWithCertificateWait(ctx context.Context, authMessage *AuthMessageWithRequestID) error {
	peerErr := h.handleMessageWithPeer(ctx, authMessage.AuthMessage)
	if peerErr == nil || h.certWaitGate == nil || !errors.Is(peerErr, auth.ErrNotAuthenticated) {
		return peerErr
	}

	identityKey := authMessage.IdentityKey.ToDERHex()
	h.log.DebugContext(ctx, "Session not yet certificate-authenticated, waiting for certificate exchange", slog.String("identityKey", identityKey))

	approved, waitErr := h.certWaitGate.wait(ctx, identityKey)
	if waitErr != nil {
		// The gate is at capacity (see certificateWaitGate.wait) - fail this
		// request rather than parking it, instead of growing an unbounded
		// number of concurrently waiting goroutines/connections.
		return errors.Join(waitErr, peerErr)
	}
	if !approved {
		return errors.Join(ErrCertificateTimeout, peerErr)
	}

	h.log.DebugContext(ctx, "Certificate exchange completed, retrying message", slog.String("identityKey", identityKey))
	return h.handleMessageWithPeer(ctx, authMessage.AuthMessage)
}

func (h *GeneralRequestHandler) handleUnauthenticated(ctx context.Context, httpResponse http.ResponseWriter, request *http.Request) error {
	if h.allowUnauthenticated {
		ctx = authctx.WithUnknownIdentity(ctx)
		h.log.DebugContext(ctx, "Allowing unauthenticated request to pass through")
		request = request.WithContext(ctx)
		h.nextHandler.ServeHTTP(httpResponse, request)
		return nil
	}
	h.log.DebugContext(ctx, "Rejecting unauthenticated request")
	return ErrAuthenticationRequired
}
