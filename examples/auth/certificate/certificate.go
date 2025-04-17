package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/bsv-blockchain/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/transport"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/utils"
	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/go-resty/resty/v2"
)

const serverAddress = "http://localhost:8080"
const trustedCertifier = "02certifieridentitykey00000000000000000000000000000000000000000000000"

func main() {
	// ========== Server Setup ==========
	fmt.Println("============================================================")
	fmt.Println("🔒 AGE VERIFICATION DEMO - SECURE AUTHENTICATION FLOW")
	fmt.Println("============================================================")

	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	sPrivKey, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
	if err != nil {
		panic(err)
	}

	serverMockedWallet := wallet.NewMockWallet(sPrivKey, walletFixtures.DefaultNonces...)

	// Define the certificate types and certifier expected
	certificateToRequest := transport.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		Types: map[string][]string{
			"age-verification": {"age"},
		},
	}

	// Middleware callback for processing received certificates
	onCertificatesReceived := func(
		senderPublicKey string,
		certs *[]wallet.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func()) {

		if certs == nil || len(*certs) == 0 {
			logger.Error("No certificates provided")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("No age verification certificate provided"))
			return
		}

		validAge := false

		for i, cert := range *certs {
			logger.Info("Certificate received", slog.Int("index", i), slog.Any("certificate", cert))

			if cert.Certificate.Subject != senderPublicKey {
				logger.Error("Certificate subject mismatch",
					slog.String("subject", cert.Certificate.Subject),
					slog.String("senderPublicKey", senderPublicKey))
				continue
			}

			if cert.Certificate.Certifier != trustedCertifier {
				logger.Error("Certificate not from trusted certifier")
				continue
			}

			if cert.Certificate.Type != "age-verification" {
				logger.Error("Unexpected certificate type")
				continue
			}

			ageVal, ok := cert.Certificate.Fields["age"]
			if !ok {
				logger.Error("No age field found")
				continue
			}

			age, err := strconv.Atoi(fmt.Sprintf("%v", ageVal))
			if err != nil {
				logger.Error("Invalid age format", slog.Any("ageField", ageVal))
				continue
			}

			if age < 18 {
				logger.Error("Age below 18", slog.Int("age", age))
				continue
			}

			logger.Info("Age verified", slog.Int("age", age))
			validAge = true
			break
		}

		if !validAge {
			logger.Error("Age verification failed")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Age verification failed. Must be 18 or older."))
			return
		}

		logger.Info("Age verification successful")
		if next != nil {
			next()
		}
	}

	opts := auth.Config{
		AllowUnauthenticated:   false,
		Logger:                 logger,
		Wallet:                 serverMockedWallet,
		CertificatesToRequest:  &certificateToRequest,
		OnCertificatesReceived: onCertificatesReceived,
	}
	middleware, err := auth.New(opts)
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ Auth middleware created")

	mux := http.NewServeMux()
	mux.Handle("/", middleware.Handler(http.HandlerFunc(pingHandler)))
	mux.Handle("/ping", middleware.Handler(http.HandlerFunc(pingHandler)))

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	go func() {
		logger.Info("Server started", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", slog.Any("error", err))
		}
	}()

	time.Sleep(1 * time.Second)
	fmt.Println("\n✅ Server initialized successfully on http://localhost:8080")
	fmt.Println("   Protected endpoints: / and /ping")
	fmt.Println("   Required: Age verification certificate (18+)")

	// ========== Client Simulation ==========
	fmt.Println("\n============================================================")
	fmt.Println("🧪 SIMULATING CLIENT AUTHENTICATION FLOW")
	fmt.Println("============================================================")

	cPrivKey, err := ec.PrivateKeyFromHex(walletFixtures.ClientPrivateKeyHex)
	if err != nil {
		panic(err)
	}

	mockedWallet := wallet.NewMockWallet(cPrivKey, walletFixtures.DefaultNonces...)

	fmt.Println("\n📡 STEP 1: Client initiates authentication handshake")
	responseData := callInitialRequest(mockedWallet)
	fmt.Printf("   ↪ Server responded with identity key: %s...\n", responseData.IdentityKey[:16])

	fmt.Println("\n📡 STEP 2: Testing access to protected resource WITHOUT certificate")
	resp := callPingEndpoint(mockedWallet, responseData)
	expectedErrorCode := http.StatusUnauthorized
	if resp.StatusCode() != expectedErrorCode {
		fmt.Printf("   ❌ ERROR: Expected status %d, but received: %d\n", expectedErrorCode, resp.StatusCode())
	} else {
		fmt.Printf("   ✅ SUCCESS: Server correctly denied access with status %d (Unauthorized)\n", expectedErrorCode)
	}

	fmt.Println("\n📡 STEP 3: Sending valid age verification certificate")
	response2 := sendCertificate(mockedWallet, responseData.IdentityKey, responseData.InitialNonce)
	if response2.StatusCode() != http.StatusOK {
		fmt.Printf("   ❌ ERROR: Certificate submission failed with status: %d\n", response2.StatusCode())
	} else {
		fmt.Println("   ✅ SUCCESS: Server accepted the age verification certificate")
	}

	fmt.Println("\n📡 STEP 4: Testing access to protected resource WITH valid certificate")
	resp = callPingEndpoint(mockedWallet, responseData)
	if resp.StatusCode() != http.StatusOK {
		fmt.Printf("   ❌ ERROR: Access denied with status: %d\n", resp.StatusCode())
	} else {
		fmt.Println("   ✅ SUCCESS: Server granted access to protected resource")
		fmt.Println("   ↪ Received response: \"Pong!\"")
	}

	fmt.Println("\n============================================================")
	fmt.Println("🎉 DEMO COMPLETED SUCCESSFULLY")
	fmt.Println("============================================================")
}

// ========== Handlers ==========

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Pong!"))
}

// ========== Client Request Helpers ==========

func callInitialRequest(mockedWallet wallet.WalletInterface) *transport.AuthMessage {
	requestData := mocks.PrepareInitialRequestBody(mockedWallet)
	url := "http://localhost:8080/.well-known/auth"
	var result transport.AuthMessage
	var errMsg any

	client := resty.New()
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(requestData).
		SetResult(&result).
		SetError(&errMsg).
		Post(url)

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	if resp.IsError() {
		log.Fatalf("Request failed: Status %d, Body: %s", resp.StatusCode(), resp.String())
	}

	fmt.Println("Response from server: ", resp.String())

	fmt.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			fmt.Println(lowerKey, strings.Join(value, ", "))
		}
	}

	return &result
}

func callPingEndpoint(mockedWallet wallet.WalletInterface, response *transport.AuthMessage) *resty.Response {
	url := "http://localhost:8080/ping"

	if response.InitialNonce == "" {
		response.InitialNonce = *response.Nonce
	}
	if response.Nonce == nil {
		response.Nonce = &response.InitialNonce
	}

	headers, err := mocks.PrepareGeneralRequestHeaders(mockedWallet, response, "/ping", "GET")
	if err != nil {
		panic(err)
	}

	var result transport.AuthMessage

	client := resty.New()
	resp, err := client.R().
		SetHeaders(headers).
		SetResult(&result).
		Get(url)

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	log.Printf("Response from server: %s", resp.String())

	fmt.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			fmt.Println(lowerKey, strings.Join(value, ", "))
		}
	}

	if resp.IsError() {
		log.Printf("Warning: Received non-success status from /ping: %d", resp.StatusCode())
	}
	return resp
}

func sendCertificate(clientWallet wallet.WalletInterface, serverIdentityKey, previousNonce string) *resty.Response {
	identityPubKey, err := clientWallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		log.Fatalf("Failed to get identity key: %v", err)
	}
	identityKey := identityPubKey.PublicKey.ToDERHex()

	nonce, err := clientWallet.CreateNonce(context.Background())
	if err != nil {
		log.Fatalf("Failed to create nonce: %v", err)
	}

	certificates := []wallet.VerifiableCertificate{
		{
			Certificate: wallet.Certificate{
				Type:         "age-verification",
				SerialNumber: "12345",
				Subject:      identityKey,
				Certifier:    trustedCertifier,
				Fields: map[string]any{
					"age": "21",
				},
				Signature: "mocksignature",
			},
			Keyring: map[string]string{"age": "symmetricKeyToField"},
		},
	}

	certMessage := transport.AuthMessage{
		Version:      "0.1",
		MessageType:  "certificateResponse",
		IdentityKey:  identityKey,
		Nonce:        &nonce,
		YourNonce:    &previousNonce,
		Certificates: &certificates,
	}

	certBytes, err := json.Marshal(certificates)
	if err != nil {
		log.Fatalf("Failed to marshal certificates: %v", err)
	}

	serverKey, err := ec.PublicKeyFromString(serverIdentityKey)
	if err != nil {
		log.Fatalf("Failed to parse server key: %v", err)
	}

	signatureArgs := &wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.DefaultAuthProtocol,
			KeyID:      fmt.Sprintf("%s %s", nonce, previousNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: serverKey,
			},
		},
		Data: certBytes,
	}

	signatureResult, err := clientWallet.CreateSignature(signatureArgs, "")
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}

	signatureBytes := signatureResult.Signature.Serialize()
	certMessage.Signature = &signatureBytes

	requestBody, err := json.Marshal(certMessage)
	if err != nil {
		log.Fatalf("Failed to marshal certificate message: %v", err)
	}
	client := resty.New()
	var result transport.AuthMessage
	var errMsg any

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(requestBody).
		SetResult(&result).
		SetError(&errMsg).
		Post("http://localhost:8080/.well-known/auth")

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	if resp.IsError() {
		log.Fatalf("Request failed: Status %d, Body: %s", resp.StatusCode(), resp.String())
	}

	fmt.Println("Response from server: ", resp.String())
	return resp
}
