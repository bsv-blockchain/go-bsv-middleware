package transport

import (
	"fmt"
	"net/http"
)

// ResponseRecorder is a custom http.ResponseWriter that records the response status code and body.
type ResponseRecorder struct {
	http.ResponseWriter
	written    bool
	statusCode int
	body       []byte
}

// NewResponseRecorder creates a new response recorder
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		written:        false,
	}
}

// GetBody retrieves the recorded response body.
func (r *ResponseRecorder) GetBody() []byte {
	return r.body
}

// WriteHeader captures the status code
func (r *ResponseRecorder) WriteHeader(statusCode int) {
	if r.written {
		return
	}
	r.statusCode = statusCode
	r.written = true
}

// Write captures the response body and ensures that WriteHeader is called at least once.
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.WriteHeader(http.StatusOK)
	}
	r.body = append(r.body, b...)
	return len(b), nil
}

// Flush writes the response header and body if they have not been written yet.
func (r *ResponseRecorder) Flush() error {
	r.ResponseWriter.WriteHeader(r.statusCode)
	if len(r.body) > 0 {
		_, err := r.ResponseWriter.Write(r.body)
		return fmt.Errorf("failed to write response body: %w", err)
	}
	return nil
}

// HasBeenWritten checks if the response has been written.
func (r *ResponseRecorder) HasBeenWritten() bool {
	return r.written
}

// GetStatusCode retrieves the status code from the ResponseRecorder.
func (r *ResponseRecorder) GetStatusCode() int {
	return r.statusCode
}

// WrapResponseWriter wraps an http.ResponseWriter with recording capabilities.
func WrapResponseWriter(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     0,
	}
}

// GetStatusCode retrieves the status code from a response writer if it's a ResponseRecorder.
func GetStatusCode(w http.ResponseWriter) (int, error) {
	if rw, ok := w.(*ResponseRecorder); ok {
		return rw.statusCode, nil
	}
	return 0, fmt.Errorf("response writer is not a response recorder")
}
