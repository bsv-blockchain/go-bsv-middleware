package testabilities

import (
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/slogx"
)

type ClientFixture interface {
	ForUser(user *testusers.UserWithWallet) (client *typescript.AuthFetch, cleanup func())
	ForKey(key string) (client *typescript.AuthFetch, cleanup func())
}

type clientFixture struct {
	testing.TB

	opts []func(*typescript.AuthFetchClientOptions)
}

func newClientFixture(t testing.TB, opts ...func(*typescript.AuthFetchClientOptions)) *clientFixture {
	return &clientFixture{
		TB:   t,
		opts: opts,
	}
}

func (f *clientFixture) ForUser(user *testusers.UserWithWallet) (client *typescript.AuthFetch, cleanup func()) {
	return f.ForKey(user.PrivKey)
}

func (f *clientFixture) ForKey(key string) (client *typescript.AuthFetch, cleanup func()) {
	opts := []func(*typescript.AuthFetchClientOptions){typescript.WithLogger(slogx.NewTestLogger(f))}
	return typescript.NewAuthFetch(wallet.PrivHex(key), append(opts, f.opts...)...)
}
