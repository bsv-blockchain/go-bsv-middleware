package assert

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/stretchr/testify/require"
)

// InitialResponseHeaders checks if the response headers are correct for the initial response.
func InitialResponseHeaders(t *testing.T, response *http.Response) {
	// Check that required headers are present
	require.NotEmpty(t, response.Header.Get(constants.HeaderVersion), "HeaderVersion header is empty")
	require.NotEmpty(t, response.Header.Get(constants.HeaderMessageType), "HeaderMessageType header is empty")
	require.NotEmpty(t, response.Header.Get(constants.HeaderIdentityKey), "HeaderIdentityKey header is empty")
	// TODO: go-sdk is not creating signature
	// require.NotEmpty(t, response.Header.Get(constants.HeaderSignature), "HeaderSignature header is empty")

	// Check specific values where appropriate
	require.Equal(t, "0.1", response.Header.Get(constants.HeaderVersion), "HeaderVersion header does not match expected value")
	require.Equal(t, "initialResponse", response.Header.Get(constants.HeaderMessageType), "HeaderMessageType header does not match expected value")
}
