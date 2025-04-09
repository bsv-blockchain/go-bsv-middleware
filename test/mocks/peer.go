package mocks

import (
	"sync"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/mock"
)

// MockPeer implements the Peer interface for testing
type MockPeer struct {
	mock.Mock

	mu                           sync.Mutex
	Sessions                     map[string]*sessionmanager.PeerSession
	generalMessageCallbacks      map[int]func(string, []byte)
	certificateReceivedCallbacks map[int]func(string, []wallet.VerifiableCertificate)
	certificateRequestCallbacks  map[int]func(string, transport.RequestedCertificateSet)
	callbackCounter              int
	lastPeerIdentityKey          string
}

// NewMockPeer creates a new mock peer for testing
func NewMockPeer() *MockPeer {
	return &MockPeer{
		Sessions:                     make(map[string]*sessionmanager.PeerSession),
		generalMessageCallbacks:      make(map[int]func(string, []byte)),
		certificateReceivedCallbacks: make(map[int]func(string, []wallet.VerifiableCertificate)),
		certificateRequestCallbacks:  make(map[int]func(string, transport.RequestedCertificateSet)),
		callbackCounter:              0,
	}
}

// ToPeer sends a message to a peer
func (m *MockPeer) ToPeer(message []byte, identityKey string, maxWaitTime int) error {
	args := m.Called(message, identityKey, maxWaitTime)
	if args.Get(0) != nil {
		return args.Get(0).(error)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	targetKey := identityKey
	if targetKey == "" {
		targetKey = m.lastPeerIdentityKey
	}
	m.lastPeerIdentityKey = targetKey
	return nil
}

// RequestCertificates requests specific certificates from a peer
func (m *MockPeer) RequestCertificates(certificatesToRequest transport.RequestedCertificateSet, identityKey string, maxWaitTime int) error {
	args := m.Called(certificatesToRequest, identityKey, maxWaitTime)
	return args.Error(0)
}

// GetAuthenticatedSession retrieves an authenticated session for a given peer identity
func (m *MockPeer) GetAuthenticatedSession(identityKey string, maxWaitTime int) (*sessionmanager.PeerSession, error) {
	args := m.Called(identityKey, maxWaitTime)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*sessionmanager.PeerSession), args.Error(1)
}

// SendCertificateResponse sends certificates to a peer in response to a request
func (m *MockPeer) SendCertificateResponse(verifierIdentityKey string, certificates []wallet.VerifiableCertificate) error {
	args := m.Called(verifierIdentityKey, certificates)
	return args.Error(0)
}

// ListenForGeneralMessages registers a callback for receiving general messages
func (m *MockPeer) ListenForGeneralMessages(callback func(senderPublicKey string, payload []byte)) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	callbackID := m.callbackCounter
	m.callbackCounter++
	m.generalMessageCallbacks[callbackID] = callback
	args := m.Called(callbackID)
	if args.Get(0) != nil {
		return args.Int(0)
	}

	return callbackID
}

// StopListeningForGeneralMessages removes a general message listener
func (m *MockPeer) StopListeningForGeneralMessages(callbackID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.generalMessageCallbacks, callbackID)
	m.Called(callbackID)
}

// ListenForCertificatesReceived registers a callback for receiving certificates
func (m *MockPeer) ListenForCertificatesReceived(callback func(senderPublicKey string, certs []wallet.VerifiableCertificate)) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	callbackID := m.callbackCounter
	m.callbackCounter++
	m.certificateReceivedCallbacks[callbackID] = callback
	args := m.Called(callbackID)
	if args.Get(0) != nil {
		return args.Int(0)
	}

	return callbackID
}

// StopListeningForCertificatesReceived removes a certificate received listener
func (m *MockPeer) StopListeningForCertificatesReceived(callbackID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certificateReceivedCallbacks, callbackID)
	m.Called(callbackID)
}

// ListenForCertificatesRequested registers a callback for certificate requests
func (m *MockPeer) ListenForCertificatesRequested(callback func(senderPublicKey string, requestedCertificates transport.RequestedCertificateSet)) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	callbackID := m.callbackCounter
	m.callbackCounter++
	m.certificateRequestCallbacks[callbackID] = callback
	args := m.Called(callbackID)
	if args.Get(0) != nil {
		return args.Int(0)
	}

	return callbackID
}

// StopListeningForCertificatesRequested removes a certificate request listener
func (m *MockPeer) StopListeningForCertificatesRequested(callbackID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certificateRequestCallbacks, callbackID)
	m.Called(callbackID)
}

// SimulateIncomingGeneralMessage simulates receiving a general message for testing
func (m *MockPeer) SimulateIncomingGeneralMessage(senderPublicKey string, payload []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, callback := range m.generalMessageCallbacks {
		go callback(senderPublicKey, payload)
	}
}

// SimulateIncomingCertificates simulates receiving certificates for testing
func (m *MockPeer) SimulateIncomingCertificates(senderPublicKey string, certificates []wallet.VerifiableCertificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, callback := range m.certificateReceivedCallbacks {
		go callback(senderPublicKey, certificates)
	}
}

// SimulateIncomingCertificateRequest simulates receiving a certificate request for testing
func (m *MockPeer) SimulateIncomingCertificateRequest(senderPublicKey string, request transport.RequestedCertificateSet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, callback := range m.certificateRequestCallbacks {
		go callback(senderPublicKey, request)
	}
}

// AddMockSession adds a session for testing
func (m *MockPeer) AddMockSession(session sessionmanager.PeerSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Sessions[*session.SessionNonce] = &session
	if session.PeerIdentityKey != nil {
		m.Sessions[*session.PeerIdentityKey] = &session
	}
}
