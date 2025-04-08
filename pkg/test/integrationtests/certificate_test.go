package integrationtests

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/assert"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/mocks"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/require"
)

const trustedCertifier = "02certifieridentitykey00000000000000000000000000000000000000000000000"

func TestAuthMiddleware_CertificateHandling(t *testing.T) {
	// given
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

	var testState struct {
		authMessage *transport.AuthMessage
	}

	t.Run("initial request with certificate requirements", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet)

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.InitialResponseHeaders(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)
		require.NotNil(t, authMessage)

		// Store the auth message for subsequent requests
		testState.authMessage = authMessage

		// Check if the auth message contains certificate requirements
		require.NotNil(t, authMessage.RequestedCertificates, "RequestedCertificates should not be nil")
		require.NotEmpty(t, authMessage.RequestedCertificates.Types, "Certificate types should not be empty")
		require.Contains(t, authMessage.RequestedCertificates.Types, "age-verification",
			"Certificate types should contain age-verification")
		require.Contains(t, authMessage.RequestedCertificates.Certifiers, trustedCertifier,
			"Certifiers should contain the trusted certifier")
	})

	t.Run("attempt access without certificate", func(t *testing.T) {
		// given
		require.NotNil(t, testState.authMessage, "Auth message should be available from previous test")

		headers, err := mocks.PrepareGeneralRequestHeaders(clientWallet, testState.authMessage, "/ping", "GET")
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, "GET", "/ping", headers, nil)

		// then
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.NotAuthorized(t, response)
	})

	t.Run("send certificate and gain access", func(t *testing.T) {
		// given
		if testState.authMessage == nil {
			t.Skip("Auth message not available, skipping test")
		}

		certificates := []wallet.VerifiableCertificate{
			{
				Certificate: wallet.Certificate{
					Type:         "age-verification",
					SerialNumber: "12345",
					Subject:      walletFixtures.ClientIdentityKey,
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

		// when
		certificateResponse, err := server.SendCertificateResponse(t, clientWallet, testState.authMessage, &certificates)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, certificateResponse)
		require.True(t, receivedCertificateFlag, "Certificate received callback should be called")

		headers, err := mocks.PrepareGeneralRequestHeaders(clientWallet, testState.authMessage, "/ping", "GET")
		require.NoError(t, err)

		response, err := server.SendGeneralRequest(t, "GET", "/ping", headers, nil)
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

	initialRequest := mocks.PrepareInitialRequestBody(clientWallet)
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
	require.NoError(t, err)
	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
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
						Subject:      walletFixtures.ClientIdentityKey,
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
						Subject:      walletFixtures.ClientIdentityKey,
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
						Subject:      walletFixtures.ClientIdentityKey,
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
						Subject:      walletFixtures.ClientIdentityKey,
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
			certResponse, err := server.SendCertificateResponse(t, clientWallet, authMessage, &tc.certificates)
			require.NoError(t, err)

			require.Equal(t, tc.expectedStatus, certResponse.StatusCode,
				"Expected HTTP status %d but got %d for certificate case: %s",
				tc.expectedStatus, certResponse.StatusCode, tc.name)

			headers, err := mocks.PrepareGeneralRequestHeaders(clientWallet, authMessage, "/ping", "GET")
			require.NoError(t, err)

			response, err := server.SendGeneralRequest(t, "GET", "/ping", headers, nil)
			require.NoError(t, err)
			assert.NotAuthorized(t, response)
		})
	}
}
