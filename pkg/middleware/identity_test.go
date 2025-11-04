package middleware_test

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/authctx"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldGetIdentity(t *testing.T) {
	t.Run("return error on missing identity", func(t *testing.T) {
		// given: context without identity
		ctx := t.Context()

		// when:
		identity, err := middleware.ShouldGetIdentity(ctx)

		// then:
		require.Error(t, err)
		assert.Nil(t, identity)
	})

	t.Run("handle unknown identity authentication", func(t *testing.T) {
		// given: context with unknown identity
		ctx := authctx.WithUnknownIdentity(t.Context())

		// when:
		identity, err := middleware.ShouldGetIdentity(ctx)

		// then:
		require.NoError(t, err)

		// and:
		assert.Truef(t, middleware.IsUnknownIdentity(identity), "identity should be unknown")
	})

	t.Run("handle authenticated identity", func(t *testing.T) {
		// given: context with unknown identity
		aliceIdentity := testusers.Alice.PublicKey(t)
		ctx := authctx.WithIdentity(t.Context(), aliceIdentity)

		// when:
		identity, err := middleware.ShouldGetIdentity(ctx)

		// then:
		require.NoError(t, err)
		assert.Equal(t, aliceIdentity, identity)

		// and:
		assert.Falsef(t, middleware.IsUnknownIdentity(identity), "identity should not be unknown")
	})
}

func TestShouldGetAuthenticatedIdentity(t *testing.T) {
	t.Run("return error on missing identity", func(t *testing.T) {
		// given: context without identity
		ctx := t.Context()

		// when:
		identity, err := middleware.ShouldGetAuthenticatedIdentity(ctx)

		// then:
		require.Error(t, err)
		assert.Nil(t, identity)
	})

	t.Run("return ErrUnknownIdentity on unknown identity", func(t *testing.T) {
		// given: context with unknown identity
		ctx := authctx.WithUnknownIdentity(t.Context())

		// when:
		identity, err := middleware.ShouldGetAuthenticatedIdentity(ctx)

		// then:
		require.ErrorIs(t, err, middleware.ErrUnknownIdentity)
		assert.Nil(t, identity)
	})

	t.Run("handle authenticated identity", func(t *testing.T) {
		// given: context with authenticated identity
		aliceIdentity := testusers.Alice.PublicKey(t)
		ctx := authctx.WithIdentity(t.Context(), aliceIdentity)

		// when:
		identity, err := middleware.ShouldGetAuthenticatedIdentity(ctx)

		// then:
		require.NoError(t, err)
		assert.Equal(t, aliceIdentity, identity)
	})
}

func TestIsNotAuthenticated(t *testing.T) {
	t.Run("missing identity", func(t *testing.T) {
		// given:
		ctx := t.Context()

		// expect:
		assert.True(t, middleware.IsNotAuthenticated(ctx))
	})

	t.Run("unknown identity", func(t *testing.T) {
		// given:
		ctx := authctx.WithUnknownIdentity(t.Context())

		// expect:
		assert.True(t, middleware.IsNotAuthenticated(ctx))
	})

	t.Run("authenticated identity", func(t *testing.T) {
		// given:
		alice := testusers.Alice.PublicKey(t)
		ctx := authctx.WithIdentity(t.Context(), alice)

		// expect:
		assert.False(t, middleware.IsNotAuthenticated(ctx))
	})
}

func TestIsNotAuthenticatedRequest(t *testing.T) {
	t.Run("missing identity", func(t *testing.T) {
		// given
		req := &http.Request{}

		// expect:
		assert.True(t, middleware.IsNotAuthenticatedRequest(req))
	})

	t.Run("unknown identity", func(t *testing.T) {
		// given:
		req := &http.Request{}
		req = req.WithContext(authctx.WithUnknownIdentity(req.Context()))

		// expect:
		assert.True(t, middleware.IsNotAuthenticatedRequest(req))
	})

	t.Run("authenticated identity", func(t *testing.T) {
		// given:
		alice := testusers.Alice.PublicKey(t)

		// and:
		req := &http.Request{}
		req = req.WithContext(authctx.WithIdentity(t.Context(), alice))

		// expect:
		assert.False(t, middleware.IsNotAuthenticatedRequest(req))
	})
}
