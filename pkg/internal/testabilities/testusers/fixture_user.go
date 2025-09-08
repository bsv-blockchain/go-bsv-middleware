package testusers

import (
	"testing"

	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
)

var Alice = User{
	Name:    "Alice",
	PrivKey: "143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c",
}

type User struct {
	Name    string
	PrivKey string
}

func (u User) IdentityKey(t testing.TB) string {
	t.Helper()
	return u.PublicKey(t).ToDERHex()
}

func (u User) PrivateKey(t testing.TB) *primitives.PrivateKey {
	t.Helper()

	priv, err := primitives.PrivateKeyFromHex(u.PrivKey)
	require.NoErrorf(t, err, "User %s has invalid private key hex %q", u.Name, u.PrivKey)
	return priv
}

func (u User) PublicKey(t testing.TB) *primitives.PublicKey {
	t.Helper()
	return u.PrivateKey(t).PubKey()
}
