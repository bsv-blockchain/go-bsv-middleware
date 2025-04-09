package auth_test

import (
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

func TestNew_PanicsWithInconsistentCertificateConfig(t *testing.T) {
	t.Run("panics with OnCertificatesReceived but no CertificatesToRequest", func(t *testing.T) {
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
		_, err = auth.New(auth.Config{
			Wallet:                 serverMockedWallet,
			SessionManager:         mockSessionManager,
			OnCertificatesReceived: onCertificatesReceived,
			CertificatesToRequest:  nil,
		})

		// then
		require.Error(t, err)
		assert.Equal(t, "OnCertificatesReceived callback is set but no certificates are requested", err.Error())

	})

	t.Run("panics with CertificatesToRequest but no OnCertificatesReceived", func(t *testing.T) {
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
		_, err = auth.New(auth.Config{
			Wallet:                 serverMockedWallet,
			SessionManager:         mockSessionManager,
			CertificatesToRequest:  certificatesToRequest,
			OnCertificatesReceived: nil,
		})

		// then
		require.Error(t, err)
		assert.Equal(t, "OnCertificatesReceived callback is required when certificates are requested", err.Error())
	})
}

func TestNew_InitializesWithValidCertificateConfig(t *testing.T) {
	t.Run("initializes with valid certificate configuration", func(t *testing.T) {
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
}

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
