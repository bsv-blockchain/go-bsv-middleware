package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/mocks"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

const serverAddress = "http://localhost:8080"
const trustedCertifier = "02certifieridentitykey00000000000000000000000000000000000000000000000"

func main() {
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	certificateToRequest := transport.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		Types: map[string][]string{
			"age-verification": {"age", "country"},
		},
	}

	// onCertificatesReceived is a function that handles the received certificates.
	// It verifies the certificates and checks if the age is 18 or above.
	onCertificatesReceived := func(
		senderPublicKey string,
		certs *[]wallet.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func()) {

		// If no certificates provided
		if certs == nil || len(*certs) == 0 {
			logger.Error("No certificates provided")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("No age verification certificate provided"))
			return
		}

		validAge := false

		for i, cert := range *certs {
			logger.Info("Certificate received", slog.Int("index", i), slog.Any("certificate", cert))

			// Verify certificate is from the correct sender
			if cert.Certificate.Subject != senderPublicKey {
				logger.Error("Certificate subject does not match sender public key",
					slog.String("subject", cert.Certificate.Subject),
					slog.String("senderPublicKey", senderPublicKey))
				continue
			}

			// Verify certificate is from trusted certifier
			if cert.Certificate.Certifier != trustedCertifier {
				logger.Error("Certificate certifier does not match trusted certifier",
					slog.String("certifier", cert.Certificate.Certifier),
					slog.String("trustedCertifier", trustedCertifier))
				continue
			}

			// Verify certificate type
			if cert.Certificate.Type != "age-verification" {
				logger.Error("Certificate type does not match requested type",
					slog.String("type", cert.Certificate.Type),
					slog.String("requestedType", "age-verification"))
				continue
			}

			// Check for age field
			ageVal, ok := cert.Certificate.Fields["age"]
			if !ok {
				logger.Error("Certificate does not contain age field")
				continue
			}

			// Convert age to int
			age, err := strconv.Atoi(fmt.Sprintf("%v", ageVal))
			if err != nil {
				logger.Error("Failed to convert age field to int", slog.Any("ageField", ageVal))
				continue
			}

			// Verify age is 18 or above
			if age < 18 {
				logger.Error("Age is below 18", slog.Int("age", age))
				continue // Skip this certificate
			} else {
				logger.Info("Age is above 17", slog.Int("age", age))
				validAge = true // Found a valid certificate
				break           // No need to check more certificates
			}
		}

		// If no valid certificate was found
		if !validAge {
			logger.Error("No valid age verification certificate found")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Age verification failed. Must be 18 or older."))
			return // Don't call next() - stop the request
		}

		// Age verification succeeded, continue with the request
		logger.Info("Age verification successful, continuing request")
		if next != nil {
			next() // Call next only if the function is provided
		}
	}

	opts := auth.Config{
		AllowUnauthenticated:   false,
		Logger:                 logger,
		Wallet:                 wallet.NewMockWallet(true, nil, walletFixtures.DefaultNonces...),
		CertificatesToRequest:  &certificateToRequest,
		OnCertificatesReceived: onCertificatesReceived,
	}
	middleware := auth.New(opts)

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

	// Create mocked client wallet with predefined client nonces and client identity key
	mockedWallet := wallet.NewMockWallet(true, &walletFixtures.ClientIdentityKey, walletFixtures.ClientNonces...)

	// Send initial request to /.well-known/auth endpoint
	responseData := callInitialRequest(mockedWallet)

	// Call /ping endpoint before sending certificate
	resp := callPingEndpoint(mockedWallet, responseData)

	//TODO Change to 400 Bad Request after changes in response finalization
	expectedErrorCode := http.StatusUnauthorized
	if resp.StatusCode != expectedErrorCode {
		fmt.Println("We should receive ", expectedErrorCode, " StatusBadRequest but got: ", resp.StatusCode)
	} else {
		fmt.Println("We didn't provide certificate so the status code is: ", expectedErrorCode)
	}
	responce2 := sendCertificate(mockedWallet, responseData.IdentityKey, responseData.InitialNonce)

	if responce2.StatusCode != http.StatusOK {
		fmt.Println("should be ok", responce2.StatusCode)
	}

	// Call /ping endpoint after sending certificate, should be authenticated now
	resp = callPingEndpoint(mockedWallet, responseData)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("should be ok", resp.StatusCode)
	}

}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Pong!"))
}

func callInitialRequest(mockedWallet wallet.WalletInterface) *transport.AuthMessage {
	fmt.Println()
	fmt.Println()
	fmt.Println("[EXAMPLE]  <---------               Preparing initial request")
	requestData := mocks.PrepareInitialRequestBody(mockedWallet)
	fmt.Println("[EXAMPLE]  Version:                ", requestData.Version)
	fmt.Println("[EXAMPLE]  Message Type:           ", requestData.MessageType)
	fmt.Println("[EXAMPLE]  Client identity key:    ", requestData.IdentityKey)
	fmt.Println("[EXAMPLE]  Initial nonce:          ", requestData.InitialNonce)

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		log.Fatalf("Failed to marshal request: %v", err)
	}

	url := "http://localhost:8080/.well-known/auth"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	log.Printf("Response from server:            %s", string(body))

	var responseData *transport.AuthMessage
	if err = json.Unmarshal(body, &responseData); err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}

	for key, value := range resp.Header {
		fmt.Println("[EXAMPLE] Header:                  ", key, value)
	}

	return responseData
}

func callPingEndpoint(mockedWallet wallet.WalletInterface, response *transport.AuthMessage) (httpResponse *http.Response) {
	fmt.Println()
	fmt.Println()
	fmt.Println("[EXAMPLE]  <---------               Preparing general request")

	url := "http://localhost:8080/ping"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

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

	for key, value := range headers {
		fmt.Println("[EXAMPLE] Header:                  ", key, value)
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	log.Printf("Response from server:            %s", string(body))
	for key, value := range resp.Header {
		fmt.Println("[EXAMPLE] Header:                  ", key, value)
	}

	return resp

}

// sendCertificate sends a certificate to the server.
func sendCertificate(clientWallet wallet.WalletInterface, serverIdentityKey, previousNonce string) *http.Response {
	identityKey, err := clientWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyOptions{IdentityKey: true})
	if err != nil {
		log.Fatalf("Failed to get identity key: %v", err)
	}

	nonce, err := clientWallet.CreateNonce(context.Background())
	if err != nil {
		log.Fatalf("Failed to create nonce: %v", err)
	}

	certificates := &[]wallet.VerifiableCertificate{
		{
			Certificate: wallet.Certificate{
				Type:         "age-verification",
				SerialNumber: "12345",
				Subject:      identityKey,
				Certifier:    trustedCertifier,
				Fields: map[string]any{
					"age": "18",
				},
				Signature: "mocksignature",
			},
			Keyring:         map[string]string{"nameOfField": "symmetricKeyToField"},
			DecryptedFields: nil,
		},
	}

	requestBody, err := json.Marshal(certificates)
	if err != nil {
		log.Fatalf("Failed to marshal certificate message: %v", err)
	}

	signature, err := clientWallet.CreateSignature(
		context.Background(), requestBody, "auth message signature",
		fmt.Sprintf("%s %s", "initialNonce", "sessionNonce"),
		identityKey)
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}

	certMessage := transport.AuthMessage{
		Version:      "0.1",
		MessageType:  "certificateResponse",
		IdentityKey:  identityKey,
		Nonce:        &nonce,
		YourNonce:    &previousNonce,
		Certificates: certificates,
		Signature:    &signature,
	}

	requestBody, err = json.Marshal(certMessage)
	if err != nil {
		log.Fatalf("Failed to marshal certificate message: %v", err)
	}

	signature, err = clientWallet.CreateSignature(
		context.Background(), requestBody, "auth message signature",
		fmt.Sprintf("%s %s", "initialNonce", "sessionNonce"),
		identityKey)
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}

	certMessage.Signature = &signature

	headers, err := mocks.PrepareGeneralRequestHeaders(clientWallet, &certMessage, "/.well-known/auth", "POST")
	if err != nil {
		panic(err)
	}

	url := "http://localhost:8080/.well-known/auth"
	req, err := http.NewRequest("POST", url, bytes.NewReader(requestBody))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	for key, value := range headers {
		fmt.Println("[EXAMPLE] Header:                  ", key, value)
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	log.Printf("Response from server:            %s", string(body))

	return resp
}
