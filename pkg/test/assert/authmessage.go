package assert

import (
	"testing"

	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/require"
)

var (
	initialResponseSignature   = []byte("mocksignaturedata")
	initialResponseAuthMessage = transport.AuthMessage{
		Version:      "0.1",
		MessageType:  "initialResponse",
		IdentityKey:  walletFixtures.ServerIdentityKey,
		InitialNonce: walletFixtures.DefaultNonces[0],
		YourNonce:    &walletFixtures.ClientNonces[0],
		Signature:    &initialResponseSignature,
	}
)

// InitialResponseAuthMessage asserts that the given AuthMessage is equal to the expected initial response AuthMessage.
func InitialResponseAuthMessage(t *testing.T, msg *transport.AuthMessage) {
	compareAuthMessage(t, &initialResponseAuthMessage, msg)
}

func compareAuthMessage(t *testing.T, expected, actual *transport.AuthMessage) {
	require.Equal(t, expected.Version, actual.Version)
	require.Equal(t, expected.MessageType, actual.MessageType)
	require.Equal(t, expected.IdentityKey, actual.IdentityKey)
	require.Equal(t, expected.InitialNonce, actual.InitialNonce)
	require.Equal(t, expected.RequestedCertificates, actual.RequestedCertificates)

	comparePointers(t, expected.Nonce, actual.Nonce)
	comparePointers(t, expected.YourNonce, actual.YourNonce)
	comparePointers(t, expected.Payload, actual.Payload)
	comparePointers(t, expected.Certificates, actual.Certificates)
	comparePointers(t, expected.Signature, actual.Signature)
}

func comparePointers(t *testing.T, expected, actual any) {
	require.Equal(t, expected, actual)
}
