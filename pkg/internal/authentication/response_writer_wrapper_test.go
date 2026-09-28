package authentication

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A handler that writes nothing gets the 200 net/http would send, so the
// status that is signed matches the status that is written (issue #145).
func TestResponseWriterWrapper_StatusCode(t *testing.T) {
	tests := map[string]struct {
		handle     func(w http.ResponseWriter)
		wantStatus int
		wantBody   string
	}{
		"nothing written": {
			handle:     func(http.ResponseWriter) {},
			wantStatus: http.StatusOK,
		},
		"only a header set": {
			handle:     func(w http.ResponseWriter) { w.Header().Set("X-Bsv-Test", "true") },
			wantStatus: http.StatusOK,
		},
		"explicit status without a body": {
			handle:     func(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) },
			wantStatus: http.StatusNoContent,
		},
		"body without an explicit status": {
			handle:     func(w http.ResponseWriter) { _, _ = w.Write([]byte("Pong!")) },
			wantStatus: http.StatusOK,
			wantBody:   "Pong!",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			wrapper := WrapResponseWriter(recorder)

			tt.handle(wrapper)

			assert.Equal(t, tt.wantStatus, wrapper.GetStatusCode(), "status used for signing")
			require.NoError(t, wrapper.Flush())
			assert.Equal(t, tt.wantStatus, recorder.Code, "status written")
			assert.Equal(t, tt.wantBody, recorder.Body.String())
		})
	}
}
