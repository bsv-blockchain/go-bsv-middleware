package auth

import (
	"log/slog"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

// Config configures the auth middleware
type Config struct {
	Wallet                 wallet.WalletInterface
	SessionManager         sessionmanager.SessionManagerInterface
	AllowUnauthenticated   bool
	Logger                 *slog.Logger
	CertificatesToRequest  *transport.RequestedCertificateSet
	OnCertificatesReceived func(
		senderPublicKey string,
		certs *[]wallet.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func(),
	)
}
