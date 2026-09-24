package authentication

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/httperror"
)

// TestDefaultErrorHandler_JSONKeyPerCode exercises every wire code
// go-bsv-middleware's toHTTPError can produce and asserts the JSON error
// body puts the human-readable text under exactly the key the TS reference
// (auth-express-middleware/src/index.ts) uses for that same code: mostly
// "description", with "message" only for CERTIFICATE_TIMEOUT and
// UNAUTHORIZED (see codesUsingMessageKey's doc comment for the TS call
// sites this is read from).
func TestDefaultErrorHandler_JSONKeyPerCode(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		wantMessage bool // true: body carries "message"; false: body carries "description"
	}{
		{name: "CERTIFICATE_TIMEOUT uses message", code: codeCertificateTimeout, wantMessage: true},
		{name: "UNAUTHORIZED uses message", code: codeUnauthorized, wantMessage: true},
		{name: "ERR_AUTH_FAILED uses description", code: "ERR_AUTH_FAILED", wantMessage: false},
		{name: "ERR_AUTH_MALFORMED uses description", code: "ERR_AUTH_MALFORMED", wantMessage: false},
		{name: "ERR_CERTIFICATES_REQUIRED uses description", code: "ERR_CERTIFICATES_REQUIRED", wantMessage: false},
		{name: "ERR_RESPONSE_SIGNING_FAILED uses description", code: "ERR_RESPONSE_SIGNING_FAILED", wantMessage: false},
		{name: "ERR_AUTH_CAPACITY uses description", code: "ERR_AUTH_CAPACITY", wantMessage: false},
		{name: "ERR_INTERNAL_SERVER_ERROR uses description", code: "ERR_INTERNAL_SERVER_ERROR", wantMessage: false},
		{name: "unknown/empty code falls back to ERR_INTERNAL_SERVER_ERROR and uses description", code: "", wantMessage: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpErr := &httperror.Error{
				StatusCode: http.StatusTeapot, // arbitrary; not under test here
				Code:       tc.code,
				Message:    "some human-readable text",
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			req.Header.Set("Accept", "application/json")
			rec := httptest.NewRecorder()

			DefaultErrorHandler(req.Context(), slog.Default(), httpErr, rec, req)

			var body map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

			assert.Equal(t, "error", body["status"])

			wantCode := tc.code
			if wantCode == "" {
				wantCode = errUnknownCode
			}
			assert.Equal(t, wantCode, body["code"])

			if tc.wantMessage {
				assert.Equal(t, "some human-readable text", body["message"], "expected \"message\" key for code %q", wantCode)
				_, hasDescription := body["description"]
				assert.False(t, hasDescription, "code %q should not also carry a \"description\" key", wantCode)
			} else {
				assert.Equal(t, "some human-readable text", body["description"], "expected \"description\" key for code %q", wantCode)
				_, hasMessage := body["message"]
				assert.False(t, hasMessage, "code %q should not also carry a \"message\" key", wantCode)
			}
		})
	}
}

// TestDefaultErrorHandler_TextPlainStillUsesRawMessage ensures the
// (Go-specific, non-TS) text/plain negotiation path is untouched by the
// description/message split, which only applies to the JSON body.
func TestDefaultErrorHandler_TextPlainStillUsesRawMessage(t *testing.T) {
	httpErr := &httperror.Error{
		StatusCode: http.StatusUnauthorized,
		Code:       codeUnauthorized,
		Message:    "plain text body",
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/plain")
	rec := httptest.NewRecorder()

	DefaultErrorHandler(req.Context(), slog.Default(), httpErr, rec, req)

	assert.Equal(t, "plain text body", rec.Body.String())
	assert.Equal(t, "text/plain", rec.Header().Get("Content-Type"))
}

func TestDefaultErrorHandler_SetsStatusCodeAndNoSniffHeader(t *testing.T) {
	httpErr := &httperror.Error{
		StatusCode: http.StatusServiceUnavailable,
		Code:       "ERR_AUTH_CAPACITY",
		Message:    "Authentication is temporarily at capacity",
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	DefaultErrorHandler(req.Context(), slog.Default(), httpErr, rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
}
