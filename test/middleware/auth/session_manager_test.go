package auth_test

import (
	"testing"

	"github.com/4chain-ag/go-bsv-middlewares/testutil/mock"
	"github.com/stretchr/testify/require"
)

// TestSessionManager_AddAndGetSession tests the AddSession and GetSession methods of the SessionManager.
// It verifies that sessions can be added and retrieved correctly.
// It also verifies that sessions can be retrieved by both sessionNonce and peerIdentityKey.
// It also verifies that the "best" session is retrieved when multiple sessions are associated with the same peerIdentityKey
func TestSessionManager_AddAndGetSession(t *testing.T) {
	sessionManager := mock.NewSessionManager()

	t.Run("Add and get session by both keys", func(t *testing.T) {
		session := mock.NewPeerSession(t)

		sessionManager.AddSession(session)

		retrievedSession := sessionManager.GetSession(*session.SessionNonce)
		require.NotNil(t, retrievedSession)
		require.Equal(t, session, *retrievedSession)

		retrievedSession = sessionManager.GetSession(*session.PeerIdentityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, session, *retrievedSession)
	})

	t.Run("Correctly get best session by both keys", func(t *testing.T) {
		sessions := mock.NewPeerSessionsForThisSameIdentityKey(t, 5)
		identityKey := *sessions[0].PeerIdentityKey

		sessionManager.AddSession(sessions[0])

		// The "best" session should be the only one
		retrievedSession := sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[0], *retrievedSession)

		sessionManager.AddSession(sessions[1])

		// The "best" session should be the most recent one
		retrievedSession = sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[1], *retrievedSession)

		sessions[2].IsAuthenticated = true
		sessionManager.AddSession(sessions[2])

		// The "best" session should be the authenticated one
		retrievedSession = sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[2], *retrievedSession)

		sessionManager.AddSession(sessions[3])

		// The "best" session should still be the authenticated one
		retrievedSession = sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[2], *retrievedSession)

		sessions[4].IsAuthenticated = true
		sessionManager.AddSession(sessions[4])

		// The "best" session should be the most recent authenticated one
		retrievedSession = sessionManager.GetSession(identityKey)
		require.NotNil(t, retrievedSession)
		require.Equal(t, sessions[4], *retrievedSession)
	})
}

func TestSessionManager_UpdateSession(t *testing.T) {
	sessionManager := mock.NewSessionManager()

	t.Run("Update session", func(t *testing.T) {
		session := mock.NewPeerSession(t)

		sessionManager.AddSession(session)

		session.IsAuthenticated = true
		sessionManager.UpdateSession(session)

		retrievedSession := sessionManager.GetSession(*session.SessionNonce)
		require.NotNil(t, retrievedSession)
		require.Equal(t, session, *retrievedSession)
	})
}

func TestSessionManager_RemoveSession(t *testing.T) {
	sessionManager := mock.NewSessionManager()

	t.Run("Remove session", func(t *testing.T) {
		session := mock.NewPeerSession(t)

		sessionManager.AddSession(session)

		sessionManager.RemoveSession(session)

		retrievedSession := sessionManager.GetSession(*session.SessionNonce)
		require.Nil(t, retrievedSession)

		retrievedSession = sessionManager.GetSession(*session.PeerIdentityKey)
		require.Nil(t, retrievedSession)
	})
}
