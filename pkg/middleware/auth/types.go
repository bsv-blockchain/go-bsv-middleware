package auth

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"log/slog"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
)

// Config configures the auth middleware
type Config struct {
	Wallet                 *wallet.Wallet
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
