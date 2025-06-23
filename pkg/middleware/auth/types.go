package auth

import (
	"log/slog"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Config contains configuration options for the auth middleware
type Config struct {
	Wallet                 wallet.Interface
	Transport              auth.Transport 
	Logger                 *slog.Logger
	SessionManager         auth.SessionManager
	AllowUnauthenticated   bool
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived auth.OnCertificateReceivedCallback
}
