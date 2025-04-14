package integrationtests

import (
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"net/http"
	"testing"

	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/test/assert"
	"github.com/4chain-ag/go-bsv-middleware/test/mocks"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware_SessionManager_HappyPath(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	var authMessage *transport.AuthMessage

	t.Run("check if session was created after initial request", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet)
		serverWallet.OnCreateNonceOnce(walletFixtures.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.InitialResponseHeaders(t, response)
		authMessage, err = mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)
		assert.InitialResponseAuthMessage(t, authMessage)

		session := sessionManager.GetSession(initialRequest.IdentityKey)
		require.NotNil(t, session)
		require.Equal(t, session.IsAuthenticated, true)
	})

	t.Run("check if session is still authenticated after general request", func(t *testing.T) {
		// given
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, authMessage, request)
		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnCreateNonceOnce(walletFixtures.DefaultNonces[1], nil)
		serverWallet.OnCreateNonceOnce(walletFixtures.DefaultNonces[2], nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: true}, nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)

		opts := wallet.GetPublicKeyArgs{IdentityKey: true}
		clientIdentityKey, err := clientWallet.GetPublicKey(&opts, "")
		require.NoError(t, err)
		session := sessionManager.GetSession(clientIdentityKey.PublicKey.ToDERHex())
		require.NotNil(t, session)
		require.Equal(t, session.IsAuthenticated, true)
	})

}
