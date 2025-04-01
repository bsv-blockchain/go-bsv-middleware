package assert

import (
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

var (
	initialResponseHeaders = map[string]string{
		"x-bsv-auth-version":      "0.1",
		"x-bsv-auth-message-type": "initialResponse",
		"x-bsv-auth-identity-key": walletFixtures.ServerIdentityKey,
		"x-bsv-auth-your-nonce":   walletFixtures.ClientNonces[0],
		"x-bsv-auth-signature":    "6d6f636b7369676e617475726564617461",
	}

	generalResponseHeaders = map[string]string{
		"x-bsv-auth-version":      "0.1",
		"x-bsv-auth-message-type": "general",
		"x-bsv-auth-identity-key": walletFixtures.ServerIdentityKey,
		"x-bsv-auth-your-nonce":   walletFixtures.ClientNonces[0],
		"x-bsv-auth-nonce":        walletFixtures.DefaultNonces[1],
		"x-bsv-auth-signature":    "6d6f636b7369676e617475726564617461",
	}
)

func InitialResponseHeaders(t *testing.T, response *http.Response) {
	for key, value := range initialResponseHeaders {
		require.Equal(t, value, response.Header.Get(key))
	}
}

func GeneralResponseHeaders(t *testing.T, response *http.Response) {
	for key, value := range generalResponseHeaders {
		require.Equal(t, value, response.Header.Get(key))
	}

	require.NotNil(t, response.Header.Get("x-bsv-auth-request-id"))
}
