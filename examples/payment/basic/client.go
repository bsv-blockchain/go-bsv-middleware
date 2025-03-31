package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/payment"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
)

func main() {
	fmt.Println("====================================")
	fmt.Println("BSV Payment Client - Demo")
	fmt.Println("====================================\n")

	clientWallet := wallet.NewMockWallet(true, &walletFixtures.ClientIdentityKey, walletFixtures.ClientNonces...)
	fmt.Println("✓ Client wallet created with identity key:", walletFixtures.ClientIdentityKey)

	fmt.Println("\n📡 STEP 1: AUTHENTICATION")
	fmt.Println("------------------------------------")
	authHeaders, err := performAuthHandshake(clientWallet)
	if err != nil {
		fmt.Printf("❌ Authentication failed: %v\n", err)
		return
	}
	fmt.Println("✓ Authentication successful!")

	fmt.Println("\n🔍 STEP 2: ACCESSING FREE ENDPOINT")
	fmt.Println("------------------------------------")
	infoData, err := accessFreeEndpoint(authHeaders)
	if err != nil {
		fmt.Printf("❌ Free endpoint access failed: %v\n", err)
		return
	}
	fmt.Println("✓ Free endpoint accessed successfully:")
	fmt.Printf("  Info data: %s\n", infoData)

	fmt.Println("\n🔍 STEP 3: INITIAL PAID REQUEST")
	fmt.Println("------------------------------------")
	paymentTerms, err := makeInitialRequest(authHeaders)
	if err != nil {
		fmt.Printf("❌ Initial request failed: %v\n", err)
		return
	}
	fmt.Printf("✓ Received 402 Payment Required with terms:\n")
	fmt.Printf("  - Satoshis required: %d\n", paymentTerms.SatoshisRequired)
	fmt.Printf("  - Derivation prefix: %s\n", paymentTerms.DerivationPrefix)
	fmt.Printf("  - Payment URL: %s\n", paymentTerms.PaymentURL)

	fmt.Println("\n💰 STEP 4: PREPARING PAYMENT")
	fmt.Println("------------------------------------")
	paymentData, err := createPayment(paymentTerms)
	if err != nil {
		fmt.Printf("❌ Payment creation failed: %v\n", err)
		return
	}
	fmt.Println("✓ Payment created successfully")

	fmt.Println("\n📤 STEP 5: SUBMITTING PAYMENT")
	fmt.Println("------------------------------------")
	weatherData, err := submitPaymentAndGetResource(authHeaders, paymentData)
	if err != nil {
		fmt.Printf("❌ Payment submission failed: %v\n", err)
		return
	}
	fmt.Println("✓ Payment accepted!")
	fmt.Println("✓ Resource retrieved successfully:")
	fmt.Printf("  Weather data: %s\n", weatherData)

	fmt.Println("\n✅ COMPLETE PAYMENT FLOW DEMONSTRATED SUCCESSFULLY")
}

func performAuthHandshake(clientWallet wallet.WalletInterface) (map[string]string, error) {
	fmt.Println("🔄 Performing authentication handshake...")

	nonce, err := clientWallet.CreateNonce(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}
	fmt.Println("→ Created client nonce:", nonce)

	identityKey, err := clientWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyOptions{IdentityKey: true})
	if err != nil {
		return nil, fmt.Errorf("failed to get identity key: %w", err)
	}
	fmt.Println("→ Using client identity key:", identityKey)

	initialRequestData := map[string]interface{}{
		"version":      "0.1",
		"messageType":  "initialRequest",
		"identityKey":  identityKey,
		"initialNonce": nonce,
	}

	url := "http://localhost:8080/.well-known/auth"
	fmt.Println("→ Sending initial request to:", url)

	jsonData, _ := json.Marshal(initialRequestData)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	fmt.Printf("← Received response: HTTP %d\n", resp.StatusCode)

	authHeaders := map[string]string{
		"x-bsv-auth-identity-key": identityKey,
		"x-bsv-auth-nonce":        resp.Header.Get("x-bsv-auth-nonce"),
		"x-bsv-auth-your-nonce":   resp.Header.Get("x-bsv-auth-your-nonce"),
		"x-bsv-auth-version":      "0.1",
	}

	fmt.Println("→ Authentication headers prepared for future requests")

	return authHeaders, nil
}

func accessFreeEndpoint(authHeaders map[string]string) (string, error) {
	fmt.Println("🔄 Accessing free endpoint (authentication only)...")

	url := "http://localhost:8080/info"
	fmt.Println("→ Requesting:", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range authHeaders {
		req.Header.Set(k, v)
	}

	req.Header.Set("x-bsv-auth-signature", "mock-signature")
	req.Header.Set("x-bsv-auth-request-id", base64.StdEncoding.EncodeToString([]byte("mock-request-id")))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	fmt.Printf("← Received response: HTTP %d\n", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(body), nil
}

func makeInitialRequest(authHeaders map[string]string) (*payment.PaymentTerms, error) {
	fmt.Println("🔄 Making initial request to paid resource (expecting 402)...")

	url := "http://localhost:8080/weather"
	fmt.Println("→ Requesting:", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range authHeaders {
		req.Header.Set(k, v)
	}

	req.Header.Set("x-bsv-auth-signature", "mock-signature")
	req.Header.Set("x-bsv-auth-request-id", "mock-request-id")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	fmt.Printf("← Received response: HTTP %d\n", resp.StatusCode)

	if resp.StatusCode != http.StatusPaymentRequired {
		return nil, fmt.Errorf("expected 402 Payment Required, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var terms payment.PaymentTerms
	if err := json.Unmarshal(body, &terms); err != nil {
		return nil, fmt.Errorf("failed to parse payment terms: %w", err)
	}

	return &terms, nil
}

func createPayment(terms *payment.PaymentTerms) (*payment.Payment, error) {
	fmt.Println("🔄 Creating payment transaction...")

	derivationSuffix := fmt.Sprintf("suffix-%d", time.Now().Unix())
	fmt.Println("→ Generated derivation suffix:", derivationSuffix)

	mockTransaction := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	fmt.Println("→ Created mock transaction with ID:", fmt.Sprintf("tx-%x", mockTransaction[:4]))

	payment := &payment.Payment{
		ModeID:           "bsv-direct",
		DerivationPrefix: terms.DerivationPrefix,
		DerivationSuffix: derivationSuffix,
		Transaction:      mockTransaction,
	}

	return payment, nil
}

func submitPaymentAndGetResource(authHeaders map[string]string, paymentData *payment.Payment) (string, error) {
	fmt.Println("🔄 Submitting payment and requesting resource...")

	url := "http://localhost:8080/weather"
	fmt.Println("→ Requesting:", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range authHeaders {
		req.Header.Set(k, v)
	}

	paymentJSON, _ := json.Marshal(paymentData)
	req.Header.Set("X-BSV-Payment", string(paymentJSON))
	fmt.Println("→ Added payment header with transaction data")

	req.Header.Set("x-bsv-auth-signature", "mock-signature")
	req.Header.Set("x-bsv-auth-request-id", base64.StdEncoding.EncodeToString([]byte("mock-request-id")))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Failed to close response body: %v\n", err)
		}
	}(resp.Body)

	fmt.Printf("← Received response: HTTP %d\n", resp.StatusCode)

	satoshisPaid := resp.Header.Get("X-BSV-Payment-Satoshis-Paid")
	if satoshisPaid != "" {
		fmt.Printf("← Payment confirmation: %s satoshis paid\n", satoshisPaid)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(body), nil
}
