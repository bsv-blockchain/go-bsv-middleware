package authentication

import (
	"context"
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"

	"github.com/go-softwarelab/common/pkg/slogx"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/httperror"
)

// errUnknownCode is used whenever an httperror.Error carries no specific
// Code, matching the TS reference's fallback error identifier.
const errUnknownCode = "ERR_INTERNAL_SERVER_ERROR"

// codeCertificateTimeout and codeUnauthorized name the two wire codes that
// use the JSON body's "message" key rather than "description" (see
// codesUsingMessageKey below). Shared constants so toHTTPError (which sets
// these codes) and DefaultErrorHandler (which special-cases them) can't
// drift apart, and so the repeated literal doesn't trip goconst.
const (
	codeCertificateTimeout = "CERTIFICATE_TIMEOUT"
	codeUnauthorized       = "UNAUTHORIZED"
)

// codesUsingMessageKey lists the wire error codes for which the TS
// reference (auth-express-middleware/src/index.ts) puts its human-readable
// text in the JSON error body's "message" field. Every other status/code
// response in that file - by far the majority - puts it in a "description"
// field instead. The two literal exceptions are:
//   - CERTIFICATE_TIMEOUT (scheduleNextOrCertificateWait's timeout branch)
//   - UNAUTHORIZED (handleUnauthenticated's "no auth headers, and
//     unauthenticated isn't allowed" response)
//
// go-bsv-middleware reuses the UNAUTHORIZED code for several other error
// conditions the TS reference does not classify under that code at all
// (e.g. a missing identity key, or a malformed handshake/general request,
// which TS reports as a 400 AuthProtocolError instead); those still use
// "message" here, since they share the one wire code TS defines "message"
// for, and this table keys strictly off the wire code, not the underlying
// cause.
var codesUsingMessageKey = map[string]bool{
	codeCertificateTimeout: true,
	codeUnauthorized:       true,
}

// errorResponseBody mirrors the BRC-103/BRC-104 wire error shape emitted by
// the TS reference (auth-express-middleware):
// {"status":"error","code":"...","description":"..."} for most codes, or
// {"status":"error","code":"...","message":"..."} for the codes in
// codesUsingMessageKey. Exactly one of Description/Message is ever set.
type errorResponseBody struct {
	Status      string `json:"status"`
	Code        string `json:"code"`
	Description string `json:"description,omitempty"`
	Message     string `json:"message,omitempty"`
}

func DefaultErrorHandler(ctx context.Context, log *slog.Logger, httpErr *httperror.Error, res http.ResponseWriter, req *http.Request) {
	log = slogx.Child(log, "DefaultErrorHandler")

	acceptType := req.Header.Get("Accept")
	mediaType, _, err := mime.ParseMediaType(acceptType)
	if err != nil {
		log.DebugContext(ctx, "Failed to parse Accept header value, will default to json response", slogx.Error(err))
	}

	code := httpErr.Code
	if code == "" {
		code = errUnknownCode
	}

	var body string
	switch mediaType {
	case "text/plain":
		res.Header().Set("Content-Type", "text/plain")
		body = httpErr.Message
	default:
		res.Header().Set("Content-Type", "application/json")
		respBody := errorResponseBody{Status: "error", Code: code}
		if codesUsingMessageKey[code] {
			respBody.Message = httpErr.Message
		} else {
			respBody.Description = httpErr.Message
		}
		encoded, marshalErr := json.Marshal(respBody)
		if marshalErr != nil {
			// This can only happen if httpErr.Message contains invalid UTF-8,
			// which json.Marshal still handles by escaping - kept defensive.
			log.ErrorContext(ctx, "Failed to encode error body as JSON", slogx.Error(marshalErr))
			encoded = []byte(`{"status":"error","code":"` + errUnknownCode + `"}`)
		}
		body = string(encoded)
	}
	res.Header().Set("X-Content-Type-Options", "nosniff")

	res.WriteHeader(httpErr.StatusCode)
	_, err = res.Write([]byte(body))
	if err != nil {
		log.ErrorContext(ctx, "Failed to write error body", slogx.Error(err), slog.String("body", body))
	}
}
