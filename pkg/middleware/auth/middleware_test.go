package auth_test

import (
	"net/http"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/assert"
)

func TestNew_PanicsWithInconsistentCertificateConfig(t *testing.T) {
	t.Run("panics with OnCertificatesReceived but no CertificatesToRequest", func(t *testing.T) {
		// given
		mockWallet := wallet.NewMockWallet(true, nil)
		mockSessionManager := sessionmanager.NewSessionManager()

		onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
			// This shouldn't be called in this test
		}

		// then - should panic
		assert.Panics(t, func() {
			auth.New(auth.Config{
				Wallet:                 mockWallet,
				SessionManager:         mockSessionManager,
				OnCertificatesReceived: onCertificatesReceived,
				CertificatesToRequest:  nil, // Missing certificate request config
			})
		})
	})

	t.Run("panics with CertificatesToRequest but no OnCertificatesReceived", func(t *testing.T) {
		// given
		mockWallet := wallet.NewMockWallet(true, nil)
		mockSessionManager := sessionmanager.NewSessionManager()

		certificatesToRequest := &transport.RequestedCertificateSet{
			Certifiers: []string{"certifier-key"},
			Types: map[string][]string{
				"test-cert": {"field1", "field2"},
			},
		}

		// then - should panic
		assert.Panics(t, func() {
			auth.New(auth.Config{
				Wallet:                 mockWallet,
				SessionManager:         mockSessionManager,
				CertificatesToRequest:  certificatesToRequest,
				OnCertificatesReceived: nil, // Missing callback
			})
		})
	})
}

func TestNew_InitializesWithValidCertificateConfig(t *testing.T) {
	t.Run("initializes with valid certificate configuration", func(t *testing.T) {
		// given
		mockWallet := wallet.NewMockWallet(true, nil)
		mockSessionManager := sessionmanager.NewSessionManager()

		certificatesToRequest := &transport.RequestedCertificateSet{
			Certifiers: []string{"certifier-key"},
			Types: map[string][]string{
				"test-cert": {"field1", "field2"},
			},
		}

		onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
			// Valid callback
		}

		// when - should not panic
		middleware := auth.New(auth.Config{
			Wallet:                 mockWallet,
			SessionManager:         mockSessionManager,
			CertificatesToRequest:  certificatesToRequest,
			OnCertificatesReceived: onCertificatesReceived,
		})

		// then
		assert.NotNil(t, middleware)
	})
}

func TestNew_DefaultSessionManager(t *testing.T) {
	t.Run("creates default session manager when none provided", func(t *testing.T) {
		// given
		mockWallet := wallet.NewMockWallet(true, nil)

		// when - should not panic
		middleware := auth.New(auth.Config{
			Wallet: mockWallet,
			// No SessionManager provided, should create a default one
		})

		// then
		assert.NotNil(t, middleware)
	})
}

func TestNew_DefaultWallet(t *testing.T) {
	t.Run("creates default wallet when none provided", func(t *testing.T) {
		// when - should not panic
		middleware := auth.New(auth.Config{
			// No Wallet provided, should create a default one
		})

		// then
		assert.NotNil(t, middleware)
	})
}

func TestNew_MisconfigurationErrors(t *testing.T) {
	t.Run("handles nil logger gracefully", func(t *testing.T) {
		// given
		mockWallet := wallet.NewMockWallet(true, nil)

		// when - should not panic
		middleware := auth.New(auth.Config{
			Wallet: mockWallet,
			Logger: nil, // No logger provided
		})

		// then
		assert.NotNil(t, middleware)
	})
}
