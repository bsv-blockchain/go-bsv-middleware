package mocks

import (
	"context"
	"errors"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/mock"
)

// CreateServerMockWallet returns a mock wallet for server with predefined keys.
func CreateServerMockWallet(key *ec.PrivateKey) wallet.WalletInterface {
	return wallet.NewMockWallet(key, walletFixtures.DefaultNonces...)
}

// CreateClientMockWallet returns a mock wallet for server with predefined nonces.
func CreateClientMockWallet() wallet.WalletInterface {
	key, err := ec.PrivateKeyFromHex(walletFixtures.ClientPrivateKeyHex)
	if err != nil {
		panic(err)
	}
	return wallet.NewMockWallet(key, walletFixtures.ClientNonces...)
}

// MockableWallet is a mock implementation of the WalletInterface.
type MockableWallet struct {
	mock.Mock
}

// NewMockableWallet creates a new instance of MockableWallet
func NewMockableWallet() *MockableWallet {
	return &MockableWallet{}
}

// GetPublicKey return mocked public key value.
func (m *MockableWallet) GetPublicKey(args *wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "GetPublicKey", args, originator) {
		return nil, errors.New("unexpected call to GetPublicKey")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.GetPublicKeyResult), call.Error(1) //nolint:wrapcheck // return mocked error
}

// CreateSignature return mocked signature value.
func (m *MockableWallet) CreateSignature(args *wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "CreateSignature", args, originator) {
		return nil, errors.New("unexpected call to CreateSignature")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.CreateSignatureResult), call.Error(1) //nolint:wrapcheck // return mocked error
}

// VerifySignature return mocked verification value.
func (m *MockableWallet) VerifySignature(args *wallet.VerifySignatureArgs) (*wallet.VerifySignatureResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "VerifySignature", args) {
		return nil, errors.New("unexpected call to VerifySignature")
	}
	call := m.Called(args)
	return call.Get(0).(*wallet.VerifySignatureResult), call.Error(1) //nolint:wrapcheck // return mocked error
}

// CreateNonce return mocked nonce value.
func (m *MockableWallet) CreateNonce(ctx context.Context) (string, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "CreateNonce", ctx) {
		return "", errors.New("unexpected call to CreateNonce")
	}
	call := m.Called(ctx)
	return call.String(0), call.Error(1)
}

// VerifyNonce return mocked verification value.
func (m *MockableWallet) VerifyNonce(ctx context.Context, nonce string) (bool, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "VerifyNonce", ctx, nonce) {
		return false, errors.New("unexpected call to VerifyNonce")
	}
	call := m.Called(ctx, nonce)
	return call.Bool(0), call.Error(1)
}

// ListCertificates return mocked certificate list value.
func (m *MockableWallet) ListCertificates(ctx context.Context, certifiers []string, types []string) ([]wallet.Certificate, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "ListCertificates", ctx, certifiers, types) {
		return nil, errors.New("unexpected call to ListCertificates")
	}
	call := m.Called(ctx, certifiers, types)
	return call.Get(0).([]wallet.Certificate), call.Error(1) //nolint:wrapcheck // return mocked error
}

// ProveCertificate return mocked certificate proof value.
func (m *MockableWallet) ProveCertificate(ctx context.Context, cert wallet.Certificate, verifier string, fieldsToReveal []string) (map[string]string, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "ProveCertificate", ctx, cert, verifier, fieldsToReveal) {
		return nil, errors.New("unexpected call to ProveCertificate")
	}
	call := m.Called(ctx, cert, verifier, fieldsToReveal)
	return call.Get(0).(map[string]string), call.Error(1) //nolint:wrapcheck // return mocked error
}

// OnGetPublicKeyOnce sets up a one-time expectation for GetPublicKey.
func (m *MockableWallet) OnGetPublicKeyOnce(result *wallet.GetPublicKeyResult, err error) *mock.Call {
	return m.On("GetPublicKey", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnCreateSignatureOnce sets up a one-time expectation for CreateSignature.
func (m *MockableWallet) OnCreateSignatureOnce(result *wallet.CreateSignatureResult, err error) *mock.Call {
	return m.On("CreateSignature", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnVerifySignatureOnce sets up a one-time expectation for VerifySignature.
func (m *MockableWallet) OnVerifySignatureOnce(result *wallet.VerifySignatureResult, err error) *mock.Call {
	return m.On("VerifySignature", mock.Anything).Return(result, err).Once()
}

// OnCreateNonceOnce sets up a one-time expectation for CreateNonce.
func (m *MockableWallet) OnCreateNonceOnce(nonce string, err error) *mock.Call {
	return m.On("CreateNonce", mock.Anything).Return(nonce, err).Once()
}

// OnVerifyNonceOnce sets up a one-time expectation for VerifyNonce.
func (m *MockableWallet) OnVerifyNonceOnce(isValid bool, err error) *mock.Call {
	return m.On("VerifyNonce", mock.Anything, mock.Anything).Return(isValid, err).Once()
}

// OnListCertificatesOnce sets up a one-time expectation for ListCertificates.
func (m *MockableWallet) OnListCertificatesOnce(certifiers, types []string, certs []wallet.Certificate, err error) *mock.Call {
	return m.On("ListCertificates", mock.Anything, certifiers, types).Return(certs, err).Once()
}

// OnProveCertificateOnce sets up a one-time expectation for ProveCertificate.
func (m *MockableWallet) OnProveCertificateOnce(cert wallet.Certificate, verifier string, fieldsToReveal []string, result map[string]string, err error) *mock.Call {
	return m.On("ProveCertificate", mock.Anything, cert, verifier, fieldsToReveal).Return(result, err).Once()
}
