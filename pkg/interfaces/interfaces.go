package interfaces

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Wallet defines the wallet operations required by the auth middleware
type Wallet interface {
	GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error)
	Encrypt(ctx context.Context, args wallet.EncryptArgs, originator string) (*wallet.EncryptResult, error)
	Decrypt(ctx context.Context, args wallet.DecryptArgs, originator string) (*wallet.DecryptResult, error)
	CreateHMAC(ctx context.Context, args wallet.CreateHMACArgs, originator string) (*wallet.CreateHMACResult, error)
	VerifyHMAC(ctx context.Context, args wallet.VerifyHMACArgs, originator string) (*wallet.VerifyHMACResult, error)
	CreateSignature(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error)
	VerifySignature(ctx context.Context, args wallet.VerifySignatureArgs, originator string) (*wallet.VerifySignatureResult, error)

	AcquireCertificate(ctx context.Context, args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error)
	ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error)
	ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error)
	RelinquishCertificate(ctx context.Context, args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error)
}

// Payment defines the payment operations required by the payment middleware.
type Payment interface {
	Wallet
	InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error)
}
