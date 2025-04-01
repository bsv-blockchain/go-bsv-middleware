package assert

import (
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"testing"
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

func readBody(t *testing.T, res *http.Response) string {
	defer func() {
		err := res.Body.Close()
		require.NoError(t, err)
	}()
	body, err := io.ReadAll(res.Body)

	require.NoError(t, err)
	return string(body)
}
