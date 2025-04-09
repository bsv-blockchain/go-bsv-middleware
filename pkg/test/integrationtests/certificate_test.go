package integrationtests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/assert"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/mocks"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
)

const trustedCertifier = "02certifieridentitykey00000000000000000000000000000000000000000000000"

func TestAuthMiddleware_CertificateHandling(t *testing.T) {
	t.Run("initial request with certificate requirements", func(t *testing.T) {
		certificateRequirements := &transport.RequestedCertificateSet{
			Certifiers: []string{trustedCertifier},
			Types: map[string][]string{
				"age-verification": {"age", "country"},
			},
		}

		onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {

			if certs != nil && len(*certs) > 0 && next != nil {
				next()
			} else {
				res.Header().Set("Content-Type", "text/plain")
				res.WriteHeader(http.StatusForbidden)
				res.Write([]byte("Invalid certificate"))
			}
		}

		server := mocks.CreateMockHTTPServer(mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		clientWallet := mocks.CreateClientMockWallet()

		initialRequest := mocks.PrepareInitialRequestBody(clientWallet)
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.InitialResponseHeaders(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)
		require.NotNil(t, authMessage)

		require.NotNil(t, authMessage.RequestedCertificates, "RequestedCertificates should not be nil")
		require.NotEmpty(t, authMessage.RequestedCertificates.Types, "Certificate types should not be empty")
		require.Contains(t, authMessage.RequestedCertificates.Types, "age-verification",
			"Certificate types should contain age-verification")
		require.Contains(t, authMessage.RequestedCertificates.Certifiers, trustedCertifier,
			"Certifiers should contain the trusted certifier")
	})

	t.Run("attempt access without certificate", func(t *testing.T) {
		certificateRequirements := &transport.RequestedCertificateSet{
			Certifiers: []string{trustedCertifier},
			Types: map[string][]string{
				"age-verification": {"age", "country"},
			},
		}

		onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {

			if certs != nil && len(*certs) > 0 && next != nil {
				next()
			} else {
				res.Header().Set("Content-Type", "text/plain")
				res.WriteHeader(http.StatusForbidden)
				res.Write([]byte("Invalid certificate"))
			}
		}

		server := mocks.CreateMockHTTPServer(mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		clientWallet := mocks.CreateClientMockWallet()

		initialRequest := mocks.PrepareInitialRequestBody(clientWallet)
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, authMessage, request)
		require.NoError(t, err)

		response, err = server.SendGeneralRequest(t, request)
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
	})

	t.Run("send certificate and gain access", func(t *testing.T) {
		certificateRequirements := &transport.RequestedCertificateSet{
			Certifiers: []string{trustedCertifier},
			Types: map[string][]string{
				"age-verification": {"age", "country"},
			},
		}

		var receivedCertificateFlag bool
		onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
			receivedCertificateFlag = true

			if certs != nil && len(*certs) > 0 && next != nil {
				next()
			} else {
				res.Header().Set("Content-Type", "text/plain")
				res.WriteHeader(http.StatusForbidden)
				res.Write([]byte("Invalid certificate"))
			}
		}

		server := mocks.CreateMockHTTPServer(mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		clientWallet := mocks.CreateClientMockWallet()

		initialRequest := mocks.PrepareInitialRequestBody(clientWallet)
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		clientIdentityKey, err := clientWallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true}, "")
		require.NoError(t, err)

		certificates := []wallet.VerifiableCertificate{
			{
				Certificate: wallet.Certificate{
					Type:         "age-verification",
					SerialNumber: "12345",
					Subject:      clientIdentityKey.PublicKey.ToDERHex(),
					Certifier:    trustedCertifier,
					Fields: map[string]any{
						"age":     "21",
						"country": "Switzerland",
					},
					Signature: "mocksignature",
				},
				Keyring: map[string]string{"age": "mockkey"},
			},
		}

		receivedCertificateFlag = false

		nonce, err := clientWallet.CreateNonce(context.Background())
		require.NoError(t, err)

		certMessage := transport.AuthMessage{
			Version:      "0.1",
			MessageType:  transport.CertificateResponse,
			IdentityKey:  clientIdentityKey.PublicKey.ToDERHex(),
			Nonce:        &nonce,
			YourNonce:    &authMessage.InitialNonce,
			Certificates: &certificates,
		}

		certBytes, err := json.Marshal(certificates)
		require.NoError(t, err)

		serverKey, err := ec.PublicKeyFromString(authMessage.IdentityKey)
		require.NoError(t, err)

		signatureArgs := &wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.DefaultAuthProtocol,
				KeyID:      fmt.Sprintf("%s %s", nonce, authMessage.InitialNonce),
				Counterparty: wallet.Counterparty{
					Type:         wallet.CounterpartyTypeOther,
					Counterparty: serverKey,
				},
			},
			Data: certBytes,
		}

		signatureResult, err := clientWallet.CreateSignature(signatureArgs, "")
		require.NoError(t, err)

		signBytes := signatureResult.Signature.Serialize()
		certMessage.Signature = &signBytes

		jsonData, err := json.Marshal(certMessage)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", server.URL()+"/.well-known/auth", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		certResponse, err := client.Do(req)
		require.NoError(t, err)
		defer certResponse.Body.Close()

		require.Equal(t, http.StatusOK, certResponse.StatusCode, "Certificate submission should return 200 OK")
		require.True(t, receivedCertificateFlag, "Certificate received callback should be called")

		request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, authMessage, request)
		require.NoError(t, err)

		response, err = server.SendGeneralRequest(t, request)
		require.NoError(t, err)
		assert.ResponseOK(t, response) // Now should be authorized
	})
}

func TestAuthMiddleware_InvalidCertificateHandling(t *testing.T) {
	// given
	certificateRequirements := &transport.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		Types: map[string][]string{
			"age-verification": {"age", "country"},
		},
	}

	onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
		if certs == nil || len(*certs) == 0 {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("No valid certificates"))
			return
		}

		cert := (*certs)[0]

		if cert.Certificate.Certifier != trustedCertifier {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Untrusted certifier"))
			return
		}

		if cert.Certificate.Type != "age-verification" {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Wrong certificate type"))
			return
		}

		ageValue, ok := cert.Certificate.Fields["age"]
		if !ok {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Missing age field"))
			return
		}

		age, err := strconv.Atoi(ageValue.(string))
		if err != nil || age < 18 {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Invalid age - must be 18+"))
			return
		}

		next()
	}

	server := mocks.CreateMockHTTPServer(mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	opts := wallet.GetPublicKeyArgs{IdentityKey: true}
	clientIdentityKey, err := clientWallet.GetPublicKey(&opts, "")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		certificates   []wallet.VerifiableCertificate
		expectedStatus int
	}{
		{
			name: "wrong certifier",
			certificates: []wallet.VerifiableCertificate{
				{
					Certificate: wallet.Certificate{
						Type:         "age-verification",
						SerialNumber: "12345",
						Subject:      clientIdentityKey.PublicKey.ToDERHex(),
						Certifier:    "wrong-certifier-key",
						Fields: map[string]any{
							"age":     "21",
							"country": "Switzerland",
						},
					},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "wrong certificate type",
			certificates: []wallet.VerifiableCertificate{
				{
					Certificate: wallet.Certificate{
						Type:         "wrong-type",
						SerialNumber: "12345",
						Subject:      clientIdentityKey.PublicKey.ToDERHex(),
						Certifier:    trustedCertifier,
						Fields: map[string]any{
							"age":     "21",
							"country": "Switzerland",
						},
					},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "missing age field",
			certificates: []wallet.VerifiableCertificate{
				{
					Certificate: wallet.Certificate{
						Type:         "age-verification",
						SerialNumber: "12345",
						Subject:      clientIdentityKey.PublicKey.ToDERHex(),
						Certifier:    trustedCertifier,
						Fields: map[string]any{
							"country": "Switzerland",
							// Age field missing
						},
					},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "underage certificate",
			certificates: []wallet.VerifiableCertificate{
				{
					Certificate: wallet.Certificate{
						Type:         "age-verification",
						SerialNumber: "12345",
						Subject:      clientIdentityKey.PublicKey.ToDERHex(),
						Certifier:    trustedCertifier,
						Fields: map[string]any{
							"age":     "17", // Underage
							"country": "Switzerland",
						},
					},
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "empty certificates",
			certificates:   []wallet.VerifiableCertificate{},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			certResponse, err := server.SendCertificateResponse(t, clientWallet, &tc.certificates)
			require.NoError(t, err)

			require.Equal(t, tc.expectedStatus, certResponse.StatusCode,
				"Expected HTTP status %d but got %d for certificate case: %s",
				tc.expectedStatus, certResponse.StatusCode, tc.name)

			request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
			require.NoError(t, err)
			response, err := server.SendGeneralRequest(t, request)
			require.NoError(t, err)
			assert.NotAuthorized(t, response)
		})
	}
}
