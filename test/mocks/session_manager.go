package mocks

import (
	"sync"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/stretchr/testify/mock"
)

// MockableSessionManager is a mock implementation of the session manager interface
type MockableSessionManager struct {
	mock.Mock

	mu                    sync.Mutex
	sessions              map[string]sessionmanager.PeerSession
	identityKeyToSessions map[string][]string
}

// NewMockableSessionManager creates a new instance of MockableSessionManager
func NewMockableSessionManager() *MockableSessionManager {
	return &MockableSessionManager{
		sessions:              make(map[string]sessionmanager.PeerSession),
		identityKeyToSessions: make(map[string][]string),
	}
}

// AddSession return mocked value or add a session to the manager.
func (m *MockableSessionManager) AddSession(session sessionmanager.PeerSession) {
	if m.isExpectedMockCall("AddSession", session) {
		m.Called(session)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if session.SessionNonce != nil {
		m.sessions[*session.SessionNonce] = session
	}
	if session.PeerIdentityKey != nil {
		sessionNonces, exists := m.identityKeyToSessions[*session.PeerIdentityKey]
		if exists {
			m.identityKeyToSessions[*session.PeerIdentityKey] = append(sessionNonces, *session.SessionNonce)
			return
		}

		m.identityKeyToSessions[*session.PeerIdentityKey] = []string{*session.SessionNonce}
	}
}

// UpdateSession return mocked value or update a session to the manager.
func (m *MockableSessionManager) UpdateSession(session sessionmanager.PeerSession) {
	if m.isExpectedMockCall("UpdateSession", session) {
		m.Called(session)
		return
	}

	m.AddSession(session)
}

// GetSession return mocked value or get a session from the manager.
func (m *MockableSessionManager) GetSession(identifier string) *sessionmanager.PeerSession {
	if m.isExpectedMockCall("GetSession", identifier) {
		args := m.Called(identifier)
		if s, ok := args.Get(0).(*sessionmanager.PeerSession); ok {
			return s
		}
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if session, ok := m.sessions[identifier]; ok {
		return &session
	}

	if nonces, ok := m.identityKeyToSessions[identifier]; ok && len(nonces) > 0 {
		if session, ok := m.sessions[nonces[0]]; ok {
			return &session
		}
	}

	return nil
}

// RemoveSession return mocked value or remove a session from the manager.
func (m *MockableSessionManager) RemoveSession(session sessionmanager.PeerSession) {
	if m.isExpectedMockCall("RemoveSession", session) {
		m.Called(session)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if session.SessionNonce != nil {
		delete(m.sessions, *session.SessionNonce)
	}
	if session.PeerIdentityKey != nil {
		delete(m.identityKeyToSessions, *session.PeerIdentityKey)
	}
}

// HasSession return mocked value or check if a session exists in the manager.
func (m *MockableSessionManager) HasSession(identifier string) bool {
	if m.isExpectedMockCall("HasSession", identifier) {
		args := m.Called(identifier)
		return args.Bool(0)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, existsNonce := m.sessions[identifier]
	nonces, existsIdentity := m.identityKeyToSessions[identifier]
	return existsNonce || (existsIdentity && len(nonces) > 0)
}

// OnAddSessionOnce sets up a one-time expectation for the AddSession method.
func (m *MockableSessionManager) OnAddSessionOnce(session sessionmanager.PeerSession) *mock.Call {
	return m.On("AddSession", session).Once()
}

// OnUpdateSessionOnce sets up a one-time expectation for the UpdateSession method.
func (m *MockableSessionManager) OnUpdateSessionOnce(session sessionmanager.PeerSession) *mock.Call {
	return m.On("UpdateSession", session).Once()
}

// OnGetSessionOnce sets up a one-time expectation for the GetSession method.
func (m *MockableSessionManager) OnGetSessionOnce(identifier string, session sessionmanager.PeerSession) *mock.Call {
	return m.On("GetSession", identifier).Return(session).Once()
}

// OnRemoveSessionOnce sets up a one-time expectation for the RemoveSession method.
func (m *MockableSessionManager) OnRemoveSessionOnce(session sessionmanager.PeerSession) *mock.Call {
	return m.On("RemoveSession", session).Once()
}

// OnHasSessionOnce sets up a one-time expectation for the HasSession method.
func (m *MockableSessionManager) OnHasSessionOnce(identifier string) *mock.Call {
	return m.On("HasSession", identifier).Once()
}

func (m *MockableSessionManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions = make(map[string]sessionmanager.PeerSession)
	m.identityKeyToSessions = make(map[string][]string)
}

func (m *MockableSessionManager) isExpectedMockCall(method string, arguments ...any) bool {
	for _, call := range m.ExpectedCalls {
		if call.Method == method {
			_, diffCount := call.Arguments.Diff(arguments)
			if diffCount == 0 {
				if call.Repeatability > -1 {
					return true
				}
			}
		}
	}
	return false
}
