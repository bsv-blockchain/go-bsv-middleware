package shared

import "time"

// PeerSession holds the session information for a peer
type PeerSession struct {
	IsAuthenticated bool
	SessionNonce    *string
	PeerNonce       *string
	PeerIdentityKey *string
	LastUpdate      time.Time
}
