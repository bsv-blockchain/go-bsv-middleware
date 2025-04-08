package assert

import (
	"encoding/hex"
	"testing"

	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/require"
)

var (
	initialResponseSignature   = []byte("3044022001b11522b8effc5ee836914d3d4bdb87e95164246fb7515ef355a3fa96c558f20220537130fb596f55476d308cd18ef9b2238b04aa828d7393082288b5872f7f1c90")
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

	if expected.Signature != nil {
		hexStr := string(*expected.Signature)

		s, err := hex.DecodeString(hexStr)
		require.NoError(t, err)

		encoded := []byte(hex.EncodeToString(s))
		require.Equal(t, *expected.Signature, encoded)
	}
}

func comparePointers(t *testing.T, expected, actual any) {
	require.Equal(t, expected, actual)
}
