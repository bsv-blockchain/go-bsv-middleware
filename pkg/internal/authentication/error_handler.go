package authentication

import (
	"context"
	"fmt"
	"log/slog"
	"mime"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/httperror"
	"github.com/go-softwarelab/common/pkg/slogx"
)

func DefaultErrorHandler(ctx context.Context, log *slog.Logger, httpErr *httperror.Error, res http.ResponseWriter, req *http.Request) {
	log = slogx.Child(log, "DefaultErrorHandler")

	acceptType := req.Header.Get("Accept")
	mediaType, _, err := mime.ParseMediaType(acceptType)
	if err != nil {
		log.WarnContext(ctx, "Failed to parse Accept header value", slogx.Error(err))
	}

	var body string
	switch mediaType {
	case "text/plain":
		res.Header().Set("Content-Type", "text/plain")
		body = httpErr.Message
	default:
		res.Header().Set("Content-Type", "application/json")
		body = fmt.Sprintf(`{"error":%q}`, httpErr.Message)
	}
	res.Header().Set("X-Content-Type-Options", "nosniff")

	res.WriteHeader(httpErr.StatusCode)
	_, err = res.Write([]byte(body))
	if err != nil {
		log.ErrorContext(ctx, "Failed to write error body", slogx.Error(err), slog.String("body", body))
	}
}
