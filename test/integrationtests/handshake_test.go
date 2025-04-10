package integrationtests

import (
	"net/http"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/test/assert"
	"github.com/4chain-ag/go-bsv-middleware/test/mocks"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware_Handshake_HappyPath(t *testing.T) {
	// given
	key, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
	require.NoError(t, err)
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.CreateServerMockWallet(key)
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	var testState struct {
		rAuthMessage *transport.AuthMessage
	}

	pingPath := server.URL() + "/ping"

	t.Run("call initial request", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet)

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.InitialResponseHeaders(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)
		assert.InitialResponseAuthMessage(t, authMessage)

		testState.rAuthMessage = authMessage
	})

	t.Run("check authorization with GET", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.GeneralResponseHeaders(t, response, 0)
	})

	t.Run("check authorization with POST", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodPost, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.GeneralResponseHeaders(t, response, 1)
	})

	t.Run("check authorization with PUT", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodPut, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.GeneralResponseHeaders(t, response, 2)
	})

	t.Run("check authorization with DELETE", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodDelete, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.GeneralResponseHeaders(t, response, 3)
	})
}

func TestAuthMiddleware_NonGeneralRequest_ErrorPath(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	t.Run("wrong version", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet).WithWrongVersion()

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnsupportedVersionError(t, response)
	})

	t.Run("missing identity key and initial nonce", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet).WithoutIdentityKeyAndNonce()

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingRequiredFieldsError(t, response)
	})
}

func TestAuthMiddleware_GeneralRequest_ErrorPath(t *testing.T) {
	// given
	key, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
	require.NoError(t, err)
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.CreateServerMockWallet(key)
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	var testState struct {
		rAuthMessage *transport.AuthMessage
	}

	pingPath := server.URL() + "/ping"

	t.Run("no auth headers", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingRequestIDError(t, response)
	})

	t.Run("wrong signature", func(t *testing.T) {
		// given
		rAuthMessage := prepareSession(t, clientWallet, server)
		testState.rAuthMessage = rAuthMessage

		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongSignature)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.InvalidHeaderError(t, response, "signature")
	})

	t.Run("wrong version", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongVersion)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnsupportedVersionError(t, response)
	})

	t.Run("wrong your nonce", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongYourNonce)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.InvalidHeaderError(t, response, "your nonce")
	})

	t.Run("wrong signature - unable to decode", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongSignatureInHex)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.FailedToParseSignatureError(t, response)
	})

	t.Run("wrong signature - unable to decode", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongSignatureInHex)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.FailedToParseSignatureError(t, response)
	})
}

func TestAuthMiddleware_WithAllowUnauthenticated_HappyPath(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithAllowUnauthenticated).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	pingPath := server.URL() + "/ping"

	t.Run("without headers", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		require.Equal(t, 200, response.StatusCode)
	})
}

func prepareSession(t *testing.T, clientWallet wallet.WalletInterface, server *mocks.MockHTTPServer) *transport.AuthMessage {
	initialRequest := mocks.PrepareInitialRequestBody(clientWallet)
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
	require.NoError(t, err)
	assert.ResponseOK(t, response)
	assert.InitialResponseHeaders(t, response)

	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
	require.NoError(t, err)
	assert.InitialResponseAuthMessage(t, authMessage)

	return authMessage
}
