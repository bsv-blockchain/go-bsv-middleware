package logging

import (
	"log/slog"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/go-softwarelab/common/pkg/slogx"
)

// AuthMessage returns a logger attribute for the given auth message.
func AuthMessage(message *auth.AuthMessage) slog.Attr {
	return slog.Group("authMsg",
		slogx.String("type", message.MessageType),
		slog.String("identityKey", message.IdentityKey.ToDERHex()),
		slog.String("initialNonce", message.InitialNonce),
		slog.String("version", message.Version),
		slog.String("nonce", message.Nonce),
		slog.String("yourNonce", message.YourNonce),
	)
}

// RequestID returns a logger attribute for the given request ID.
func RequestID(requestID string) slog.Attr {
	if requestID == "" {
		requestID = "<unknown>"
	}
	return slog.String("requestID", requestID)
}
