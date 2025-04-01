package integrationtests

import (
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/test/assert"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/mocks"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware_Handshake_HappyPath(t *testing.T) {
	// given
	server := mocks.CreateMockHTTPServer().WithMiddleware()
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	var testState struct {
		rAuthMessage *transport.AuthMessage
	}

	t.Run("call initial request", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet)

		// when
		response, rAuthMessage, err := server.SendNonGeneralRequest(t, initialRequest)

		// then
		require.NoError(t, err)
		assert.InitialResponseHeaders(t, response)
		assert.InitialResponseAuthMessage(t, rAuthMessage)

		testState.rAuthMessage = rAuthMessage
	})

	t.Run("check authorization", func(t *testing.T) {
		// given
		headers, err := mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, "GET", "/ping", headers, nil)

		// then
		require.NoError(t, err)
		assert.GeneralResponseHeaders(t, response)
	})
}
