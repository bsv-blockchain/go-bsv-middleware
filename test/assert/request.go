package assert

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// ResponseOK checks if the response status code is 200.
func ResponseOK(t *testing.T, res *http.Response) {
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode)
}

// NotAuthorized checks if the response status code is 401.
func NotAuthorized(t *testing.T, res *http.Response) {
	require.NotNil(t, res)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

// MissingRequestIDError checks if the response body contains the "missing request ID" error.
func MissingRequestIDError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "missing request ID", errString)
}

// UnsupportedVersionError checks if the response body contains the "unsupported version" error.
func UnsupportedVersionError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "unsupported version", errString)
}

// DecodingSignatureError checks if the response body contains the "error decoding signature" error.
func DecodingSignatureError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "error decoding signature", errString)
}

// UnableToVerifyNonceError checks if the response body contains the "unable to verify nonce" error.
func UnableToVerifyNonceError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Contains(t, errString, "unable to verify nonce")
}

// FailedToParseSignatureError checks if the response body contains the "failed to parse signature" error.
func FailedToParseSignatureError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Contains(t, errString, "failed to parse signature, malformed signature")
}

// UnableToVerifySignatureError checks if the response body contains the "unable to verify signature" error.
func UnableToVerifySignatureError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Contains(t, errString, "unable to verify signature")
}

// MissingRequiredFieldsError checks if the response body contains the "missing required fields in initial request" error.
func MissingRequiredFieldsError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "missing required fields in initial request", errString)
}

// SessionNotFoundError check if the response body contain the "session not found" error.
func SessionNotFoundError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "session not found", errString)
}

// SessionNotAuthenticatedError check if the response body contain the "session not authenticated" error.
func SessionNotAuthenticatedError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "session not authenticated", errString)
}

// MissingHeaderError check if the response body contain the "missing X header" error.
func MissingHeaderError(t *testing.T, res *http.Response, header string) {
	errString := readBody(t, res)
	require.Equal(t, fmt.Sprintf("missing %s header", header), errString)
}

// InvalidHeaderError check if the response body contain the "invalid X header" error.
func InvalidHeaderError(t *testing.T, res *http.Response, header string) {
	errString := readBody(t, res)
	require.Equal(t, fmt.Sprintf("invalid %s header", header), errString)
}

func readBody(t *testing.T, res *http.Response) string {
	defer func() {
		err := res.Body.Close()
		require.NoError(t, err)
	}()
	body, err := io.ReadAll(res.Body)

	require.NoError(t, err)
	return string(body)
}
