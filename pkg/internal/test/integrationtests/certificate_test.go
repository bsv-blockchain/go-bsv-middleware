package integrationtests

// TODO: Go SDK session management check before

// import (
// 	"encoding/base64"
// 	"errors"
// 	"net/http"
// 	"strconv"
// 	"testing"

// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/test/mocks"
// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/test/testutils"
// 	"github.com/bsv-blockchain/go-sdk/auth"
// 	"github.com/bsv-blockchain/go-sdk/auth/certificates"
// 	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
// 	"github.com/bsv-blockchain/go-sdk/chainhash"
// 	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
// 	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
// 	"github.com/bsv-blockchain/go-sdk/transaction"
// 	"github.com/bsv-blockchain/go-sdk/wallet"
// 	"github.com/stretchr/testify/require"
// )

// var (
// 	trustedCertifier, _ = primitives.PublicKeyFromString(mocks.ServerIdentityKey)
// 	clientPrivateKey, _ = primitives.PrivateKeyFromHex(mocks.ClientPrivateKeyHex)
// 	clientIdentityKey   = clientPrivateKey.PubKey()
// )

// func TestAuthMiddleware_InvalidCertificateHandling(t *testing.T) {
// 	// given
// 	var certType wallet.CertificateType
// 	copy(certType[:], "age-verification")
// 	certificateRequirements := &sdkUtils.RequestedCertificateSet{
// 		// Certifiers: []wallet.HexBytes33{tu.GetByte33FromString(trustedCertifier.ToDERHex()[:32])},
// 		Certifiers: []*ec.PublicKey{trustedCertifier},
// 		CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
// 			certType: []string{"age", "country"},
// 		},
// 	}

// 	onCertificatesReceived := func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
// 		if len(certs) == 0 {
// 			return errors.New("no certificates received")
// 		}

// 		cert := (certs)[0]

// 		if cert.Certificate.Certifier.ToDERHex() != trustedCertifier.ToDERHex() {
// 			return errors.New("invalid certifier")
// 		}

// 		// Decode the certificate type to check it
// 		typeBytes, err := base64.StdEncoding.DecodeString(string(cert.Certificate.Type))
// 		if err != nil {
// 			return errors.New("invalid certificate type encoding")
// 		}

// 		if string(typeBytes) != "age-verification" {
// 			return errors.New("invalid certificate type")
// 		}

// 		ageValue, ok := cert.Certificate.Fields["age"]
// 		if !ok {
// 			return errors.New("missing age field")
// 		}

// 		// Decode the age field
// 		ageBytes, err := base64.StdEncoding.DecodeString(string(ageValue))
// 		if err != nil {
// 			return errors.New("invalid age field encoding")
// 		}

// 		age, err := strconv.Atoi(string(ageBytes))
// 		if err != nil || age < 18 {
// 			return errors.New("underage certificate")
// 		}
// 		return nil
// 	}

// 	txidBytes := []byte{
// 		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
// 		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
// 		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
// 		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
// 	}

// 	txID, err := chainhash.NewHash(txidBytes)
// 	require.NoError(t, err)

// 	sessionManager := mocks.NewMockableSessionManager()
// 	serverWallet := mocks.NewMockableWallet()

// 	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
// 		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
// 		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
// 	defer server.Close()

// 	clientWallet := mocks.CreateClientMockWallet()
// 	opts := wallet.GetPublicKeyArgs{IdentityKey: true}
// 	clientIdentityKey, err := clientWallet.GetPublicKey(t.Context(), opts, "")
// 	require.NoError(t, err)

// 	testCases := []struct {
// 		name           string
// 		certificates   []*certificates.VerifiableCertificate
// 		expectedStatus int
// 	}{
// 		{
// 			name: "wrong certifier",
// 			certificates: func() []*certificates.VerifiableCertificate {
// 				wrongCertifierKey, err := ec.PublicKeyFromString("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
// 				if err != nil {
// 					t.Fatalf("failed to create wrong certifier key: %v", err)
// 				}
// 				return []*certificates.VerifiableCertificate{
// 					{
// 						Certificate: certificates.Certificate{
// 							Type:         wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("age-verification"))),
// 							SerialNumber: wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("12345"))),
// 							Subject:      *clientIdentityKey.PublicKey,
// 							Certifier:    *wrongCertifierKey,
// 							Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
// 								"age":     wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("21"))),
// 								"country": wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("Switzerland"))),
// 							},
// 							Signature: []byte("mocksignature"),
// 							RevocationOutpoint: &transaction.Outpoint{
// 								Txid:  *txID,
// 								Index: 0,
// 							},
// 						},
// 						Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
// 					},
// 				}
// 			}(),
// 			expectedStatus: http.StatusForbidden,
// 		},
// 		{
// 			name: "wrong certificate type",
// 			certificates: func() []*certificates.VerifiableCertificate {
// 				certifierKey, err := ec.PublicKeyFromString(trustedCertifier.ToDERHex())
// 				if err != nil {
// 					t.Fatalf("failed to create certifier key: %v", err)
// 				}
// 				return []*certificates.VerifiableCertificate{
// 					{
// 						Certificate: certificates.Certificate{
// 							Type:         wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("wrong-type"))),
// 							SerialNumber: wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("12345"))),
// 							Subject:      *clientIdentityKey.PublicKey,
// 							Certifier:    *certifierKey,
// 							Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
// 								"age":     wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("21"))),
// 								"country": wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("Switzerland"))),
// 							},
// 							Signature: []byte("mocksignature"),
// 							RevocationOutpoint: &transaction.Outpoint{
// 								Txid:  *txID,
// 								Index: 0,
// 							},
// 						},
// 						Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
// 					},
// 				}
// 			}(),
// 			expectedStatus: http.StatusForbidden,
// 		},
// 		{
// 			name: "missing age field",
// 			certificates: func() []*certificates.VerifiableCertificate {
// 				certifierKey, err := ec.PublicKeyFromString(trustedCertifier.ToDERHex())
// 				if err != nil {
// 					t.Fatalf("failed to create certifier key: %v", err)
// 				}
// 				return []*certificates.VerifiableCertificate{
// 					{
// 						Certificate: certificates.Certificate{
// 							Type:         wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("age-verification"))),
// 							SerialNumber: wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("12345"))),
// 							Subject:      *clientIdentityKey.PublicKey,
// 							Certifier:    *certifierKey,
// 							Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
// 								"country": wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("Switzerland"))),
// 								// Age field missing
// 							},
// 							Signature: []byte("mocksignature"),
// 							RevocationOutpoint: &transaction.Outpoint{
// 								Txid:  *txID,
// 								Index: 0,
// 							},
// 						},
// 						Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
// 					},
// 				}
// 			}(),
// 			expectedStatus: http.StatusForbidden,
// 		},
// 		{
// 			name: "underage certificate",
// 			certificates: func() []*certificates.VerifiableCertificate {
// 				certifierKey, err := ec.PublicKeyFromString(trustedCertifier.ToDERHex())
// 				if err != nil {
// 					t.Fatalf("failed to create certifier key: %v", err)
// 				}
// 				return []*certificates.VerifiableCertificate{
// 					{
// 						Certificate: certificates.Certificate{
// 							Type:         wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("age-verification"))),
// 							SerialNumber: wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("12345"))),
// 							Subject:      *clientIdentityKey.PublicKey,
// 							Certifier:    *certifierKey,
// 							Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
// 								// Underage
// 								"age":     wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("17"))),
// 								"country": wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("Switzerland"))),
// 							},
// 							Signature: []byte("mocksignature"),
// 							RevocationOutpoint: &transaction.Outpoint{
// 								Txid:  *txID,
// 								Index: 0,
// 							},
// 						},
// 						Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
// 					},
// 				}
// 			}(),
// 			expectedStatus: http.StatusForbidden,
// 		},
// 		{
// 			name:           "empty certificates",
// 			certificates:   []*certificates.VerifiableCertificate{},
// 			expectedStatus: http.StatusForbidden,
// 		},
// 	}

// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
// 			serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
// 			serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
// 			serverWallet.OnCreateHMACOnce(&wallet.CreateHMACResult{
// 				HMAC: []byte("mockhmacsignature"),
// 			}, nil)
// 			serverWallet.OnVerifyHMACOnce(&wallet.VerifyHMACResult{
// 				Valid: true,
// 			}, nil)

// 			serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{
// 				Valid: true,
// 			}, nil)

// 			sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
// 				IsAuthenticated: true,
// 				SessionNonce:    mocks.DefaultNonces[0],
// 				PeerNonce:       mocks.DefaultNonces[0],
// 				PeerIdentityKey: clientIdentityKey.PublicKey,
// 				LastUpdate:      1747241090788,
// 			})

// 			certificateResponse, err := server.SendCertificateResponseWithSetNonces(t, clientWallet, tc.certificates, mocks.DefaultNonces[0], mocks.DefaultNonces[0])
// 			require.NoError(t, err)

// 			require.Equal(t, tc.expectedStatus, certificateResponse.StatusCode, "Certificate submission should return expected status code")

// 			request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
// 			require.NoError(t, err)
// 			response, err := server.SendGeneralRequest(t, request)
// 			require.NoError(t, err)
// 			testutils.NotAuthorized(t, response)
// 		})
// 	}
// }

// func TestAuthMiddleware_CertificateHandling(t *testing.T) {
// 	sessionManager := mocks.NewMockableSessionManager()
// 	serverWallet := mocks.NewMockableWallet()

// 	// TODO: Uncomment this when the go-sdk will support sending requested certificates
// 	// t.Run("initial request with certificate requirements", func(t *testing.T) {
// 	// 	certificateRequirements := &sdkUtils.RequestedCertificateSet{
// 	// 		Certifiers: []string{trustedCertifier.ToDERHex()},
// 	// 		CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
// 	// 			"age-verification": []string{"age", "country"},
// 	// 		},
// 	// 	}

// 	// 	var onCertificatesReceived auth.OnCertificateReceivedCallback = func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
// 	// 		if len(certs) <= 0 {
// 	// 			return errors.New("no valid certificates")
// 	// 		}

// 	// 		return nil
// 	// 	}

// 	// 	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
// 	// 		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
// 	// 		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
// 	// 	defer server.Close()

// 	// 	clientWallet := mocks.CreateClientMockWallet()

// 	// 	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
// 	// 	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
// 	// 	require.NoError(t, err)
// 	// 	assert.ResponseOK(t, response)
// 	// 	assert.InitialResponseHeaders(t, response)

// 	// 	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
// 	// 	require.NoError(t, err)
// 	// 	require.NotNil(t, authMessage)

// 	// 	require.NotNil(t, authMessage.RequestedCertificates, "RequestedCertificates should not be nil")
// 	// 	require.NotEmpty(t, authMessage.RequestedCertificates.CertificateTypes, "Certificate types should not be empty")
// 	// 	require.Contains(t, authMessage.RequestedCertificates.CertificateTypes, "age-verification",
// 	// 		"Certificate types should contain age-verification")
// 	// 	require.Contains(t, authMessage.RequestedCertificates.Certifiers, trustedCertifier,
// 	// 		"Certifiers should contain the trusted certifier")
// 	// })

// 	t.Run("attempt access without certificate", func(t *testing.T) {
// 		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
// 		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
// 		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
// 		serverWallet.OnCreateHMACOnce(&wallet.CreateHMACResult{
// 			HMAC: []byte("mockhmacsignature"),
// 		}, nil)
// 		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{
// 			Valid: true,
// 		}, nil)

// 		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
// 			IsAuthenticated: false,
// 			SessionNonce:    mocks.DefaultNonces[0],
// 			PeerNonce:       mocks.DefaultNonces[0],
// 			PeerIdentityKey: clientIdentityKey,
// 			LastUpdate:      1747241090788,
// 		})

// 		var certType wallet.CertificateType
// 		copy(certType[:], "age-verification")
// 		certificateRequirements := &sdkUtils.RequestedCertificateSet{
// 			Certifiers: []*ec.PublicKey{trustedCertifier},
// 			CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
// 				certType: []string{"age", "country"},
// 			},
// 		}

// 		var onCertificatesReceived auth.OnCertificateReceivedCallback = func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
// 			if len(certs) <= 0 {
// 				return errors.New("no valid certificates")
// 			}

// 			return nil
// 		}

// 		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
// 			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
// 			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
// 		defer server.Close()

// 		clientWallet := mocks.CreateClientMockWallet()

// 		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
// 		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
// 		require.NoError(t, err)
// 		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
// 		require.NoError(t, err)

// 		request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
// 		require.NoError(t, err)
// 		err = mocks.PrepareGeneralRequestHeadersWithSetNonces(t.Context(), clientWallet, authMessage, request, mocks.DefaultNonces[0], mocks.DefaultNonces[0])
// 		require.NoError(t, err)

// 		response, err = server.SendGeneralRequest(t, request)
// 		require.NoError(t, err)
// 		testutils.BadRequest(t, response)
// 	})

// 	t.Run("send certificate and gain access", func(t *testing.T) {
// 		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
// 		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
// 		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
// 		serverWallet.OnCreateHMACOnce(&wallet.CreateHMACResult{
// 			HMAC: []byte("mockhmacsignature"),
// 		}, nil)
// 		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{
// 			Valid: true,
// 		}, nil)

// 		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
// 			IsAuthenticated: false,
// 			SessionNonce:    mocks.DefaultNonces[0],
// 			PeerNonce:       mocks.DefaultNonces[0],
// 			PeerIdentityKey: clientIdentityKey,
// 			LastUpdate:      1747241090788,
// 		})
// 		var certType wallet.CertificateType
// 		copy(certType[:], "age-verification")
// 		certificateRequirements := &sdkUtils.RequestedCertificateSet{
// 			Certifiers: []*ec.PublicKey{trustedCertifier},
// 			CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
// 				certType: []string{"age", "country"},
// 			},
// 		}

// 		var receivedCertificateFlag bool
// 		var onCertificatesReceived auth.OnCertificateReceivedCallback = func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
// 			receivedCertificateFlag = true

// 			if len(certs) <= 0 {
// 				return errors.New("no valid certificates")
// 			}

// 			return nil
// 		}

// 		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
// 			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
// 			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
// 		defer server.Close()

// 		clientWallet := mocks.CreateClientMockWallet()

// 		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
// 		_, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
// 		require.NoError(t, err)

// 		clientIDKey, err := clientWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
// 		require.NoError(t, err)

// 		certifierPubKey, err := ec.PublicKeyFromString(trustedCertifier.ToDERHex())
// 		require.NoError(t, err)

// 		certificates := []*certificates.VerifiableCertificate{
// 			{
// 				Certificate: certificates.Certificate{
// 					Type:         wallet.StringBase64("age-verification"),
// 					SerialNumber: wallet.StringBase64("12345"),
// 					Subject:      *clientIDKey.PublicKey,
// 					Certifier:    *certifierPubKey,
// 					Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
// 						"age":     wallet.StringBase64("21"),
// 						"country": wallet.StringBase64("Switzerland"),
// 					},
// 					Signature: []byte("mocksignature"),
// 				},
// 				Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
// 					"age": wallet.StringBase64("mockkey"),
// 				},
// 			},
// 		}

// 		receivedCertificateFlag = false

// 		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
// 		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
// 		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
// 		serverWallet.OnCreateHMACOnce(&wallet.CreateHMACResult{
// 			HMAC: []byte("mockhmacsignature"),
// 		}, nil)
// 		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{
// 			Valid: true,
// 		}, nil)

// 		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
// 			IsAuthenticated: false,
// 			SessionNonce:    mocks.DefaultNonces[0],
// 			PeerNonce:       mocks.DefaultNonces[0],
// 			PeerIdentityKey: clientIdentityKey,
// 			LastUpdate:      1747241090788,
// 		})

// 		// then

// 		certResponse, err := server.SendCertificateResponseWithSetNonces(t, clientWallet, certificates, mocks.DefaultNonces[0], mocks.DefaultNonces[0])
// 		require.NoError(t, err)
// 		require.Equal(t, http.StatusOK, certResponse.StatusCode, "Certificate submission should return 200 OK")
// 		require.True(t, receivedCertificateFlag, "Certificate received callback should be called")
// 	})
// }
