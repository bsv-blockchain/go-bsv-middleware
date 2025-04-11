package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errWalletRequired       = errors.New("wallet is required")
	errMissingCertsCallback = errors.New("OnCertificatesReceived callback is required when certificates are requested")
	errMissingCertsRequest  = errors.New("OnCertificatesReceived callback is set but no certificates are requested")
)

// SETUP-1: Missing Wallet Instance
func TestNew_MissingWallet(t *testing.T) {
	// when
	middleware, err := auth.New(auth.Config{
		// No wallet provided
	})

	// then
	assert.Nil(t, middleware)
	assert.Error(t, err)
	assert.Equal(t, errWalletRequired.Error(), err.Error())
	assert.True(t, errors.Is(err, errWalletRequired) || err.Error() == errWalletRequired.Error())
}

// SETUP-2: Default Session Manager Creation
func TestNew_DefaultSessionManager(t *testing.T) {
	t.Run("creates default session manager when none provided", func(t *testing.T) {
		// given
		sPrivKey, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
		if err != nil {
			panic(err)
		}

		serverMockedWallet := wallet.NewMockWallet(sPrivKey, walletFixtures.DefaultNonces...)

		// when
		middleware, err := auth.New(auth.Config{
			Wallet: serverMockedWallet,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, middleware)
	})
}

// SETUP-3: Default Logger Creation
func TestNew_DefaultLogger(t *testing.T) {
	// given
	key, err := ec.NewPrivateKey()
	require.NoError(t, err)
	mockWallet := wallet.NewMockWallet(key)

	// when
	middleware, err := auth.New(auth.Config{
		Wallet: mockWallet,
		// No logger provided
	})

	// then
	assert.NoError(t, err)
	assert.NotNil(t, middleware)
}

// SETUP-4: AllowUnauthenticated Flag Configuration
func TestNew_AllowUnauthenticatedFlag(t *testing.T) {
	// given
	key, err := ec.NewPrivateKey()
	require.NoError(t, err)
	mockWallet := wallet.NewMockWallet(key)

	t.Run("Flag set to true", func(t *testing.T) {
		// when
		middleware, err := auth.New(auth.Config{
			Wallet:               mockWallet,
			AllowUnauthenticated: true,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, middleware)

		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		assert.NotNil(t, handler)
	})

	t.Run("Flag set to false", func(t *testing.T) {
		// when
		middleware, err := auth.New(auth.Config{
			Wallet:               mockWallet,
			AllowUnauthenticated: false,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, middleware)

		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		assert.NotNil(t, handler)
	})
}

// Certificate configuration validation tests
func TestNew_InconsistentCertificateConfig(t *testing.T) {
	t.Run("error with OnCertificatesReceived but no CertificatesToRequest", func(t *testing.T) {
		// given
		sPrivKey, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
		if err != nil {
			panic(err)
		}

		serverMockedWallet := wallet.NewMockWallet(sPrivKey, walletFixtures.DefaultNonces...)
		mockSessionManager := sessionmanager.NewSessionManager()

		onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
		}

		// when
		middleware, err := auth.New(auth.Config{
			Wallet:                 serverMockedWallet,
			SessionManager:         mockSessionManager,
			OnCertificatesReceived: onCertificatesReceived,
			CertificatesToRequest:  nil,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, middleware)
		assert.Equal(t, errMissingCertsRequest.Error(), err.Error())
		assert.True(t, errors.Is(err, errMissingCertsRequest) || err.Error() == errMissingCertsRequest.Error())
	})

	t.Run("error with CertificatesToRequest but no OnCertificatesReceived", func(t *testing.T) {
		// given
		sPrivKey, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
		if err != nil {
			panic(err)
		}

		serverMockedWallet := wallet.NewMockWallet(sPrivKey, walletFixtures.DefaultNonces...)
		mockSessionManager := sessionmanager.NewSessionManager()

		certificatesToRequest := &transport.RequestedCertificateSet{
			Certifiers: []string{"certifier-key"},
			Types: map[string][]string{
				"test-cert": {"field1", "field2"},
			},
		}

		// when
		middleware, err := auth.New(auth.Config{
			Wallet:                 serverMockedWallet,
			SessionManager:         mockSessionManager,
			CertificatesToRequest:  certificatesToRequest,
			OnCertificatesReceived: nil,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, middleware)
		assert.Equal(t, errMissingCertsCallback.Error(), err.Error())
		assert.True(t, errors.Is(err, errMissingCertsCallback) || err.Error() == errMissingCertsCallback.Error())
	})
}

func TestNew_ValidCertificateConfig(t *testing.T) {
	t.Run("success with valid certificate configuration", func(t *testing.T) {
		// given
		sPrivKey, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
		if err != nil {
			panic(err)
		}

		serverMockedWallet := wallet.NewMockWallet(sPrivKey, walletFixtures.DefaultNonces...)
		mockSessionManager := sessionmanager.NewSessionManager()

		certificatesToRequest := &transport.RequestedCertificateSet{
			Certifiers: []string{"certifier-key"},
			Types: map[string][]string{
				"test-cert": {"field1", "field2"},
			},
		}

		onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
		}

		// when
		middleware, err := auth.New(auth.Config{
			Wallet:                 serverMockedWallet,
			SessionManager:         mockSessionManager,
			CertificatesToRequest:  certificatesToRequest,
			OnCertificatesReceived: onCertificatesReceived,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, middleware)
	})

	t.Run("success with neither certificate option provided", func(t *testing.T) {
		// given
		key, err := ec.NewPrivateKey()
		require.NoError(t, err)
		mockWallet := wallet.NewMockWallet(key)
		mockSessionManager := sessionmanager.NewSessionManager()

		// when
		middleware, err := auth.New(auth.Config{
			Wallet:                 mockWallet,
			SessionManager:         mockSessionManager,
			CertificatesToRequest:  nil,
			OnCertificatesReceived: nil,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, middleware)
	})
}
