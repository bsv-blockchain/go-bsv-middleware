package auth

import (
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
)

// Config configures the auth middleware
type Config struct {
	Wallet                 interfaces.Wallet
	SessionManager         auth.SessionManager
	AllowUnauthenticated   bool
	Logger                 *slog.Logger
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived func(
		senderPublicKey string,
		certs []*certificates.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func(),
	)
}
