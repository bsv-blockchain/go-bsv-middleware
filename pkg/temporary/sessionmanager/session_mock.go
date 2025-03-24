package sessionmanager

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// NewPeerSession creates a new PeerSession with random values.
func NewPeerSession(t *testing.T) PeerSession {
	sNonce, err := randomHex(32)
	require.NoError(t, err)
	pNonce, err := randomHex(32)
	require.NoError(t, err)
	pIdentityKey, err := randomHex(66)
	require.NoError(t, err)

	return PeerSession{
		IsAuthenticated: false,
		SessionNonce:    &sNonce,
		PeerNonce:       &pNonce,
		PeerIdentityKey: &pIdentityKey,
		LastUpdate:      time.Now(),
	}
}

// NewPeerSessionsForThisSameIdentityKey creates a slice of PeerSessions with the same PeerIdentityKey.
func NewPeerSessionsForThisSameIdentityKey(t *testing.T, count int) []PeerSession {
	pIdentityKey, err := randomHex(66)
	require.NoError(t, err)

	sessions := make([]PeerSession, count)
	for i := 0; i < count; i++ {
		sNonce, err := randomHex(32)
		require.NoError(t, err)
		pNonce, err := randomHex(32)
		require.NoError(t, err)

		sessions[i] = PeerSession{
			IsAuthenticated: false,
			SessionNonce:    &sNonce,
			PeerNonce:       &pNonce,
			PeerIdentityKey: &pIdentityKey,
			LastUpdate:      time.Now(),
		}
	}

	return sessions
}

func randomHex(n uint) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("error during creating random hex: %w", err)
	}
	return hex.EncodeToString(b), nil
}
