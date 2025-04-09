package mocks

import (
	"sync"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/stretchr/testify/mock"
)

type MockableSessionManager struct {
	mock.Mock

	mu                   sync.Mutex
	sessions             map[string]sessionmanager.PeerSession
	identityKeyToSession map[string][]string
}

func NewMockableSessionManager() *MockableSessionManager {
	return &MockableSessionManager{
		sessions:             make(map[string]sessionmanager.PeerSession),
		identityKeyToSession: make(map[string][]string),
	}
}

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
		key := *session.PeerIdentityKey
		m.identityKeyToSession[key] = append(m.identityKeyToSession[key], *session.SessionNonce)
	}
}

func (m *MockableSessionManager) UpdateSession(session sessionmanager.PeerSession) {
	m.AddSession(session)
}

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

	if nonces, ok := m.identityKeyToSession[identifier]; ok && len(nonces) > 0 {
		if session, ok := m.sessions[nonces[0]]; ok {
			return &session
		}
	}

	return nil
}

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
		delete(m.identityKeyToSession, *session.PeerIdentityKey)
	}
}

func (m *MockableSessionManager) HasSession(identifier string) bool {
	if m.isExpectedMockCall("HasSession", identifier) {
		args := m.Called(identifier)
		return args.Bool(0)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, existsNonce := m.sessions[identifier]
	nonces, existsIdentity := m.identityKeyToSession[identifier]
	return existsNonce || (existsIdentity && len(nonces) > 0)
}

func (m *MockableSessionManager) OnAddSessionOnce(session sessionmanager.PeerSession) *mock.Call {
	return m.On("AddSession", session).Once()
}

func (m *MockableSessionManager) OnUpdateSessionOnce(session sessionmanager.PeerSession) *mock.Call {
	return m.On("UpdateSession", session).Once()
}

func (m *MockableSessionManager) OnGetSessionOnce(identifier string, session sessionmanager.PeerSession) *mock.Call {
	return m.On("GetSession", identifier).Return(session).Once()
}

func (m *MockableSessionManager) OnRemoveSessionOnce(session sessionmanager.PeerSession) *mock.Call {
	return m.On("RemoveSession", session).Once()
}

func (m *MockableSessionManager) OnHasSessionOnce(identifier string) *mock.Call {
	return m.On("HasSession", identifier).Once()
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
