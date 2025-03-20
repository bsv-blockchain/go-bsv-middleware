package mock

import (
	"sync"

	"github.com/4chain-ag/go-bsv-middlewares/pkg/middleware/shared"
)

// SessionManager is a mock implementation of the SessionManager interface.
type SessionManager struct {
	mu sync.Mutex
	// sessions is a map of sessionNonce to a Session
	sessions map[string]shared.PeerSession
	// identityKeyToSessions is a map of peerIdentityKey to a list of sessionNonce's
	identityKeyToSessions map[string][]string
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:              make(map[string]shared.PeerSession),
		identityKeyToSessions: make(map[string][]string),
	}
}

// AddSession adds a session to the manager, associating it with its sessionNonce and also with its peerIdentityKey.
func (m *SessionManager) AddSession(session shared.PeerSession) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session.SessionNonce != nil {
		m.sessions[*session.SessionNonce] = session
	}

	if session.PeerIdentityKey != nil {
		sessionNonces, exists := m.identityKeyToSessions[*session.PeerIdentityKey]
		if exists {
			m.identityKeyToSessions[*session.PeerIdentityKey] = append(sessionNonces, *session.SessionNonce)
		} else {
			m.identityKeyToSessions[*session.PeerIdentityKey] = []string{*session.SessionNonce}
		}
	}
}

// GetSession retrieves a "best" session based on a given identifier, which can be a sessionNonce or a peerIdentityKey.
func (m *SessionManager) GetSession(identifier string) *shared.PeerSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	// try to get session by sessionNonce
	if session, exists := m.sessions[identifier]; exists {
		return &session
	}

	// check if sessions exists by peerIdentityKey
	sessionNonces, exists := m.identityKeyToSessions[identifier]
	if !exists {
		return nil
	}

	// get the "best" session
	var bestSession *shared.PeerSession
	for _, sessionNonce := range sessionNonces {
		session, exists := m.sessions[sessionNonce]
		if !exists {
			continue
		}

		// update bestSession if:
		// - bestSession is nil
		// - session is authenticated and bestSession is not
		// - session and bestSession are authenticated but session is more recent than bestSession
		// - session is more recent than bestSession
		if bestSession == nil ||
			session.IsAuthenticated && (!bestSession.IsAuthenticated || session.LastUpdate.After(bestSession.LastUpdate)) ||
			!bestSession.IsAuthenticated && session.LastUpdate.After(bestSession.LastUpdate) {
			bestSession = &session
		}
	}

	return bestSession
}

// RemoveSession removes a session from the manager by clearing all associated identifiers.
func (m *SessionManager) RemoveSession(session shared.PeerSession) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session.SessionNonce != nil {
		delete(m.sessions, *session.SessionNonce)
	}

	if session.PeerIdentityKey != nil {
		sessionNonces, exists := m.identityKeyToSessions[*session.PeerIdentityKey]
		if !exists {
			return
		}
		removeSessionNonce(sessionNonces, *session.SessionNonce)
	}
}

// HasSession checks if a session exists for a given identifier (either sessionNonce or identityKey).
func (m *SessionManager) HasSession(identifier string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.sessions[identifier]
	return exists
}

// UpdateSession updates a session in the manager.
func (m *SessionManager) UpdateSession(session shared.PeerSession) {
	m.AddSession(session)
}

func removeSessionNonce(slice []string, target string) []string {
	newSlice := slice[:0] // Reuse the same slice memory
	for _, str := range slice {
		if str != target {
			newSlice = append(newSlice, str)
		}
	}
	return newSlice
}
