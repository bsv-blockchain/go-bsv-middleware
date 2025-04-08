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

		// Simple validation - in real app would verify certificate contents
		if certs != nil && len(*certs) > 0 && next != nil {
			next() // Authenticate the session
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
		// The test currently fails on this assertion
		require.NotNil(t, authMessage.RequestedCertificates, "RequestedCertificates should not be nil")
		require.NotEmpty(t, authMessage.RequestedCertificates.Types, "Certificate types should not be empty")
		require.Contains(t, authMessage.RequestedCertificates.Types, "age-verification",
			"Certificate types should contain age-verification")
		require.Contains(t, authMessage.RequestedCertificates.Certifiers, trustedCertifier,
			"Certifiers should contain the trusted certifier")
	})

	t.Run("attempt access without certificate", func(t *testing.T) {
		// given
		// First ensure we have a valid auth message
		require.NotNil(t, testState.authMessage, "Auth message should be available from previous test")

		// Create headers for the request
		headers, err := mocks.PrepareGeneralRequestHeaders(clientWallet, testState.authMessage, "/ping", "GET")
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, "GET", "/ping", headers, nil)

		// then - should be unauthorized because we haven't sent a certificate yet
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.NotAuthorized(t, response)
	})

	t.Run("send certificate and gain access", func(t *testing.T) {
		// given
		// Skip this test if auth message is nil
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

		// Reset flag to track if the callback is called
		receivedCertificateFlag = false

		// when
		certificateResponse, err := server.SendCertificateResponse(t, clientWallet, testState.authMessage, &certificates)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, certificateResponse)
		require.True(t, receivedCertificateFlag, "Certificate received callback should be called")

		// Try accessing after certificate is verified
		headers, err := mocks.PrepareGeneralRequestHeaders(clientWallet, testState.authMessage, "/ping", "GET")
		require.NoError(t, err)

		response, err := server.SendGeneralRequest(t, "GET", "/ping", headers, nil)
		require.NoError(t, err)
		assert.ResponseOK(t, response) // Now should be authorized
	})
}

// TestAuthMiddleware_InvalidCertificateHandling tests invalid certificate handling scenarios
func TestAuthMiddleware_InvalidCertificateHandling(t *testing.T) {
	// given
	certificateRequirements := &transport.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		Types: map[string][]string{
			"age-verification": {"age", "country"},
		},
	}

	// This is the important part - the test callback function needs to properly
	// use the response writer and not error out later in the process
	onCertificatesReceived := func(senderPublicKey string, certs *[]wallet.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
		// Validation that checks actual certificate content
		if certs == nil || len(*certs) == 0 {
			// Add appropriate headers
			res.Header().Set("Content-Type", "text/plain")
			// Set status and write response in a single coherent block
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("No valid certificates"))
			return
		}

		cert := (*certs)[0]

		// Check certifier
		if cert.Certificate.Certifier != trustedCertifier {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Untrusted certifier"))
			return
		}

		// Check type
		if cert.Certificate.Type != "age-verification" {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Wrong certificate type"))
			return
		}

		// Check fields
		ageValue, ok := cert.Certificate.Fields["age"]
		if !ok {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Missing age field"))
			return
		}

		// Convert age and check if valid
		age, err := strconv.Atoi(ageValue.(string))
		if err != nil || age < 18 {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Invalid age - must be 18+"))
			return
		}

		// All checks passed
		next()
	}

	server := mocks.CreateMockHTTPServer(mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	// Setup initial auth
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
			// Send the certificate
			certResponse, err := server.SendCertificateResponse(t, clientWallet, authMessage, &tc.certificates)
			require.NoError(t, err)

			// Check status code - should match the expected forbidden status
			require.Equal(t, tc.expectedStatus, certResponse.StatusCode,
				"Expected HTTP status %d but got %d for certificate case: %s",
				tc.expectedStatus, certResponse.StatusCode, tc.name)

			// Try to access protected endpoint to verify we're still unauthorized
			headers, err := mocks.PrepareGeneralRequestHeaders(clientWallet, authMessage, "/ping", "GET")
			require.NoError(t, err)

			response, err := server.SendGeneralRequest(t, "GET", "/ping", headers, nil)
			require.NoError(t, err)
			assert.NotAuthorized(t, response) // Should still be unauthorized
		})
	}
}
