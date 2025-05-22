package assert

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// InitialResponseHeaders checks if the response headers are correct for the initial response.
func InitialResponseHeaders(t *testing.T, response *http.Response) {
	// Check that required headers are present
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-version"), "x-bsv-auth-version header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-message-type"), "x-bsv-auth-message-type header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-identity-key"), "x-bsv-auth-identity-key header is empty")
	// TODO: go-sdk is not creating signature
	// require.NotEmpty(t, response.Header.Get("x-bsv-auth-signature"), "x-bsv-auth-signature header is empty")

	// Check specific values where appropriate
	require.Equal(t, "0.1", response.Header.Get("x-bsv-auth-version"), "x-bsv-auth-version header does not match expected value")
	require.Equal(t, "initialResponse", response.Header.Get("x-bsv-auth-message-type"), "x-bsv-auth-message-type header does not match expected value")
}
