package assert

import (
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"testing"
)

func ResponseOK(t *testing.T, res *http.Response) {
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode)
}

func NotAuthorized(t *testing.T, res *http.Response) {
	require.NotNil(t, res)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func MissingRequestIDError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "missing request ID", errString)
}

func UnsupportedVersionError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "unsupported version", errString)
}

func DecodingSignatureError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "error decoding signature", errString)
}

func UnableToVerifyNonceError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Contains(t, errString, "unable to verify nonce")
}

func UnableToVerifySignatureError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Contains(t, errString, "unable to verify signature")
}

func MissingRequiredFieldsError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "missing required fields in initial request", errString)
}

func readBody(t *testing.T, res *http.Response) string {
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)

	require.NoError(t, err)
	return string(body)
}
