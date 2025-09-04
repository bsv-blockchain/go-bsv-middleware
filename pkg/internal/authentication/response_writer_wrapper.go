package authentication

import (
	"fmt"
	"net/http"
	"strconv"
)

// ResponseWriterWrapper is a custom http.ResponseWriter that records the response status code and body.
type ResponseWriterWrapper struct {
	http.ResponseWriter
	headersWritten bool
	statusCode     int
	body           []byte
}

// WriteHeader implements http.ResponseWriter, but prevents the response from being written until it is flushed.
func (r *ResponseWriterWrapper) WriteHeader(statusCode int) {
	if r.headersWritten {
		return
	}

	if statusCode < 100 || statusCode > 999 {
		panic("invalid status code:" + strconv.Itoa(statusCode))
	}

	r.statusCode = statusCode
	r.headersWritten = true
}

// Write implements http.ResponseWriter, but prevents the response from being written until it is flushed.
func (r *ResponseWriterWrapper) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	if !r.headersWritten {
		r.WriteHeader(http.StatusOK)
	}
	return len(b), nil
}

// GetBody retrieves the recorded response body.
func (r *ResponseWriterWrapper) GetBody() []byte {
	return r.body
}

// Flush writes the response header and body if they have not been headersWritten yet.
func (r *ResponseWriterWrapper) Flush() error {
	if r.statusCode < 100 {
		return fmt.Errorf("response status code is not set")
	}
	r.ResponseWriter.WriteHeader(r.statusCode)
	if len(r.body) > 0 {
		_, err := r.ResponseWriter.Write(r.body)
		if err != nil {
			return fmt.Errorf("error while writing response: %w", err)
		}
	}

	return nil
}

// HasBeenWritten checks if the response has been headersWritten.
func (r *ResponseWriterWrapper) HasBeenWritten() bool {
	return r.headersWritten
}

// GetStatusCode retrieves the status code from the ResponseWriterWrapper.
func (r *ResponseWriterWrapper) GetStatusCode() int {
	return r.statusCode
}

// WrapResponseWriter wraps and tracks write status.
func WrapResponseWriter(w http.ResponseWriter) *ResponseWriterWrapper {
	return &ResponseWriterWrapper{
		ResponseWriter: w,
		statusCode:     0,
	}
}
