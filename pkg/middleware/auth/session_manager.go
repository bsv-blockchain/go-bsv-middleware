package auth

import "github.com/4chain-ag/go-bsv-middlewares/pkg/middleware/shared"

// SessionManager is an interface for managing peer sessions.
type SessionManager interface {
	// AddSession adds a session to the manager, associating it with its sessionNonce,
	// and also with its peerIdentityKey (if any). This does NOT overwrite existing
	// sessions for the same peerIdentityKey, allowing multiple concurrent sessions.
	AddSession(session shared.PeerSession)
	// UpdateSession updates a session in the manager.
	UpdateSession(session shared.PeerSession)
	// GetSession retrieves a session based on a given identifier, which can be:
	// - A sessionNonce, or
	// - A peerIdentityKey.
	// If it is a `sessionNonce`, returns that exact session.
	// If it is a `peerIdentityKey`, returns the "best" (e.g. most recently updated,
	// authenticated) session associated with that peer, if any.
	GetSession(identifier string) *shared.PeerSession
	// RemoveSession removes a session from the manager by clearing all associated identifiers.
	RemoveSession(session shared.PeerSession)
	// HasSession checks if a session exists for a given identifier (either sessionNonce or identityKey).
	// Returns true if the session exists, false otherwise.
	HasSession(identifier string) bool
}
