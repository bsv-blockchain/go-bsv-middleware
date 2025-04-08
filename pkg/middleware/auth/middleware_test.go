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
		}

		// then
		assert.Panics(t, func() {
			auth.New(auth.Config{
				Wallet:                 mockWallet,
				SessionManager:         mockSessionManager,
				OnCertificatesReceived: onCertificatesReceived,
				CertificatesToRequest:  nil,
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

		// then
		assert.Panics(t, func() {
			auth.New(auth.Config{
				Wallet:                 mockWallet,
				SessionManager:         mockSessionManager,
				CertificatesToRequest:  certificatesToRequest,
				OnCertificatesReceived: nil,
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
		}

		// when
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

		// when
		middleware := auth.New(auth.Config{
			Wallet: mockWallet,
		})

		// then
		assert.NotNil(t, middleware)
	})
}

func TestNew_DefaultWallet(t *testing.T) {
	t.Run("creates default wallet when none provided", func(t *testing.T) {
		// when
		middleware := auth.New(auth.Config{})

		// then
		assert.NotNil(t, middleware)
	})
}

func TestNew_MisconfigurationErrors(t *testing.T) {
	t.Run("handles nil logger gracefully", func(t *testing.T) {
		// given
		mockWallet := wallet.NewMockWallet(true, nil)

		// when
		middleware := auth.New(auth.Config{
			Wallet: mockWallet,
			Logger: nil,
		})

		// then
		assert.NotNil(t, middleware)
	})
}
