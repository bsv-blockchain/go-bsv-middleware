package auth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Wallet interface defines the methods that the wallet must implement
type Wallet interface {
	wallet.KeyOperations
}

// Config configures the auth middleware
type Config struct {
	Wallet                 Wallet
	SessionManager         sessionmanager.SessionManagerInterface
	AllowUnauthenticated   bool
	Logger                 *slog.Logger
	CertificatesToRequest  *transport.RequestedCertificateSet
	OnCertificatesReceived func(
		senderPublicKey string,
		certs []*certificates.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func(),
	)
}
