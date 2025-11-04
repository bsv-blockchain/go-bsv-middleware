package fixture

import (
	"fmt"

	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// WIF is a test fixture credential for internal testing purposes only
// nosemgrep: hardcoded-credential
const WIF = "L1cReZseWmqcYra3vrqj9TPBGHhvDQFD2jYuu1RUj5rrfpVLiKHs" // gitleaks:allow

type identity struct {
	WIF        string
	Identity   string
	PrivateKey *primitives.PrivateKey
	PublicKey  *primitives.PublicKey
}

var ServerIdentity identity = createIdentity()

func createIdentity() identity {
	key, err := primitives.PrivateKeyFromWif(WIF)
	if err != nil {
		panic(fmt.Errorf("invalid test setup: failed to restore key from wif: %w", err))
	}

	pubKey := key.PubKey()
	identityKey := pubKey.ToDERHex()

	return identity{
		WIF:        WIF,
		Identity:   identityKey,
		PrivateKey: key,
		PublicKey:  pubKey,
	}
}
