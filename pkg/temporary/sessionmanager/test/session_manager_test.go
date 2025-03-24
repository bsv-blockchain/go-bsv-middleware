package auth_test

import (
	"testing"

	"github.com/4chain-ag/go-bsv-middlewares/pkg/temporary/sessionmanager"
	"github.com/stretchr/testify/require"
)

func TestSessionManager_HappyPath(t *testing.T) {
	sessionManager := sessionmanager.NewSessionManager()

	t.Run("Add and get session by both keys", func(t *testing.T) {
		// given
		session := sessionmanager.NewPeerSession(t)

		// when
		sessionManager.AddSession(session)

		// then
		retrievedSession := sessionManager.GetSession(*session.SessionNonce)
		require.NotNil(t, retrievedSession)
		require.Equal(t, session, *retrievedSession)

		retrievedSession = sessionManager.GetSession(*session.PeerIdentityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, session, *retrievedSession)
	})

	t.Run("Correctly get best session by both keys", func(t *testing.T) {
		// given
		sessions := sessionmanager.NewPeerSessionsForThisSameIdentityKey(t, 5)
		identityKey := *sessions[0].PeerIdentityKey

		// when
		sessionManager.AddSession(sessions[0])

		// then - the "best" session should be the only one
		retrievedSession := sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[0], *retrievedSession)

		// when
		sessionManager.AddSession(sessions[1])

		// then - the "best" session should be the most recent one
		retrievedSession = sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[1], *retrievedSession)

		// when
		sessions[2].IsAuthenticated = true
		sessionManager.AddSession(sessions[2])

		// then - the "best" session should be the authenticated one
		retrievedSession = sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[2], *retrievedSession)

		// when
		sessionManager.AddSession(sessions[3])

		// then - the "best" session should still be the authenticated one
		retrievedSession = sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[2], *retrievedSession)

		// when
		sessions[4].IsAuthenticated = true
		sessionManager.AddSession(sessions[4])

		// then - the "best" session should be the most recent authenticated one
		retrievedSession = sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[4], *retrievedSession)
	})

	t.Run("Update session", func(t *testing.T) {
		// given
		session := sessionmanager.NewPeerSession(t)
		sessionManager.AddSession(session)

		// when
		session.IsAuthenticated = true
		sessionManager.UpdateSession(session)

		// then
		retrievedSession := sessionManager.GetSession(*session.SessionNonce)
		require.NotNil(t, retrievedSession)
		require.Equal(t, session, *retrievedSession)
	})

	t.Run("Remove session", func(t *testing.T) {
		// given
		session := sessionmanager.NewPeerSession(t)
		sessionManager.AddSession(session)

		// when
		sessionManager.RemoveSession(session)

		// then
		retrievedSession := sessionManager.GetSession(*session.SessionNonce)
		require.Nil(t, retrievedSession)

		retrievedSession = sessionManager.GetSession(*session.PeerIdentityKey)
		require.Nil(t, retrievedSession)
	})
}

func TestSessionManager_ErrorPath(t *testing.T) {
	sessionManager := sessionmanager.NewSessionManager()

	t.Run("Get non-existent session", func(t *testing.T) {
		// given
		invalidKey := "non-existent-key"

		// when
		retrievedSession := sessionManager.GetSession(invalidKey)

		// then
		require.Nil(t, retrievedSession)
	})

	t.Run("Remove non-existent session", func(t *testing.T) {
		// given
		session := sessionmanager.NewPeerSession(t)

		// when
		sessionManager.RemoveSession(session)

		// then
		retrievedSession := sessionManager.GetSession(*session.SessionNonce)
		require.Nil(t, retrievedSession)
	})

	t.Run("Update non-existent session", func(t *testing.T) {
		// given
		session := sessionmanager.NewPeerSession(t)

		// when
		sessionManager.UpdateSession(session)

		// then
		retrievedSession := sessionManager.GetSession(*session.SessionNonce)
		require.NotNil(t, retrievedSession)
		require.Equal(t, session, *retrievedSession)
	})
}
