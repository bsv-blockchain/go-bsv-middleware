package authentication

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/authctx"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/go-softwarelab/common/pkg/slogx"
)

const maxToPeerWaitTime = 30000

var ErrInvalidNonGeneralRequest = fmt.Errorf("bad request")
var ErrInvalidGeneralRequest = fmt.Errorf("invalid authentication")
var ErrProcessingMessageByPeer = fmt.Errorf("error while processing message by peer")
var ErrAuthenticationRequired = fmt.Errorf("authentication required")

type AuthRequestHandler interface {
	Handle(ctx context.Context, response http.ResponseWriter, request *http.Request) error
}

type NonGeneralRequestHandler struct {
	log                   *slog.Logger
	handleMessageWithPeer func(context.Context, *auth.AuthMessage) error
}

func (h *NonGeneralRequestHandler) Handle(ctx context.Context, _ http.ResponseWriter, request *http.Request) error {
	log := h.log

	log.DebugContext(ctx, "handling non-general request")

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
}

func (h *GeneralRequestHandler) Handle(ctx context.Context, httpResponse http.ResponseWriter, request *http.Request) error {
	log := h.log

	log.DebugContext(ctx, "handling general request")

	authMessage, err := extractGeneralAuthMessage(request)
	if err != nil {
		if errors.Is(err, ErrAuthenticationRequired) {
			return h.handleUnauthenticated(ctx, httpResponse, request)
		}
		return errors.Join(ErrInvalidGeneralRequest, err)
	}

	ctx = authctx.WithIdentity(ctx, authMessage.IdentityKey)

	log = log.With(logging.RequestID(authMessage.RequestID), logging.AuthMessage(authMessage.AuthMessage))

	log.DebugContext(ctx, "auth message extracted from request")

	if err := h.handleMessageWithPeer(ctx, authMessage.AuthMessage); err != nil {
		return errors.Join(ErrProcessingMessageByPeer, err)
	}
	h.log.DebugContext(ctx, "message successfully processed with peer")

	h.log.DebugContext(ctx, "passing request to next handler")

	response := WrapResponseWriter(httpResponse)

	ctx = authctx.WithResponse(ctx, response)
	request = request.WithContext(ctx)

	h.nextHandler.ServeHTTP(response, request)

	h.log.DebugContext(ctx, "preparing payload from response for signing")
	responsePayload, err := authpayload.FromResponse(
		authMessage.RequestIDBytes,
		authpayload.SimplifiedHttpResponse{
			StatusCode: response.GetStatusCode(),
			Header:     response.Header(),
			Body:       response.GetBody(),
		})
	if err != nil {
		return fmt.Errorf("failed to create response payload: %w", err)
	}

	h.log.DebugContext(ctx, "sending response to peer")
	err = h.peer.ToPeer(ctx, responsePayload, authMessage.IdentityKey, maxToPeerWaitTime)
	if err != nil {
		return fmt.Errorf("failed to send response to peer: %w", err)
	}

	h.log.DebugContext(ctx, "writing http response")
	err = response.Flush()
	if err != nil {
		h.log.Error("Failed to write http response", slogx.Error(err))
		// if this failed we can't do anything more about this error.
		return nil
	}

	return nil
}

func (h *GeneralRequestHandler) handleUnauthenticated(ctx context.Context, httpResponse http.ResponseWriter, request *http.Request) error {
	if h.allowUnauthenticated {
		ctx = authctx.WithUnknownIdentity(ctx)
		h.log.DebugContext(ctx, "Allowing unauthenticated request to pass through")
		request = request.WithContext(ctx)
		h.nextHandler.ServeHTTP(httpResponse, request)
		return nil
	}
	h.log.WarnContext(ctx, "Rejecting unauthenticated request")
	return ErrAuthenticationRequired
}
