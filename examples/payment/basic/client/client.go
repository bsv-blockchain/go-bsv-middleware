package main

//TODO: Implement a basic payment example for a BSV wallet application

// import (
// 	"context"
// 	"encoding/json"
// 	"log"
// 	"net/http"
// 	"time"

// 	exampleWallet "github.com/bsv-blockchain/go-bsv-middleware-examples/example-wallet"
// 	"github.com/bsv-blockchain/go-sdk/wallet"

// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/payment"
// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/utils"
// 	"github.com/bsv-blockchain/go-sdk/auth"

// 	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
// 	"github.com/go-resty/resty/v2"
// )

// const (
// 	clientPrivateKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
// 	serverURL           = "http://localhost:8080"
// )

// func main() {
// 	log.Println("BSV Payment Client - Demo")

// 	sPrivKey, err := ec.PrivateKeyFromHex(clientPrivateKeyHex)
// 	if err != nil {
// 		log.Fatalf("Failed to create private key: %v", err)
// 	}

// 	mockWallet, err := exampleWallet.NewExtendedProtoWallet(sPrivKey)
// 	if err != nil {
// 		log.Fatalf("Failed to create mock wallet: %v", err)
// 	}
// 	log.Println("✓ Client wallet created")

// 	time.Sleep(1 * time.Second)

// 	log.Println("\n📡 STEP 1: AUTHENTICATION")
// 	authResponse := authenticate(context.Background(), mockWallet)
// 	log.Println("✓ Auth complete")

// 	log.Println("\n🔍 STEP 2: ACCESS FREE ENDPOINT")
// 	callFree(context.Background(), mockWallet, authResponse)
// 	log.Println("✓ Free endpoint OK")

// 	log.Println("\n💸 STEP 3: REQUEST PREMIUM (no payment)")
// 	terms := requestPremium(context.Background(), mockWallet, authResponse)
// 	log.Printf("✓ 402 received: %d satoshis required", terms.SatoshisRequired)

// 	log.Println("\n💰 STEP 4: CREATE PAYMENT")
// 	mockPayment := createMockPayment(terms)
// 	log.Println("✓ Payment prepared")

// 	log.Println("\n💳 STEP 5: ACCESS PREMIUM (with payment)")
// 	payPremium(context.Background(), mockWallet, authResponse, mockPayment)
// 	log.Println("✓ Premium content received")
// }

// func authenticate(ctx context.Context, wallet wallet.Interface) *auth.AuthMessage {
// 	client := resty.New()
// 	reqBody := utils.PrepareInitialRequestBody(ctx, wallet)

// 	var result auth.AuthMessage
// 	var errMsg any

// 	resp, err := client.R().
// 		SetHeader("Content-Type", "application/json").
// 		SetBody(reqBody).
// 		SetResult(&result).
// 		SetError(&errMsg).
// 		Post(serverURL + "/.well-known/auth")

// 	if err != nil {
// 		log.Fatalf("Failed to send auth request: %v", err)
// 	}

// 	if resp.IsError() {
// 		log.Fatalf("Auth failed: Status %d, Body: %s", resp.StatusCode(), resp.String())
// 	}

// 	return &result
// }

// func callFree(ctx context.Context, wallet wallet.Interface, auth *auth.AuthMessage) {
// 	client := resty.New()
// 	url := serverURL + "/info"

// 	requestData := utils.RequestData{
// 		Method: http.MethodGet,
// 		URL:    url,
// 	}

// 	headers, err := utils.PrepareGeneralRequestHeaders(ctx, wallet, auth, requestData)
// 	if err != nil {
// 		log.Fatalf("Failed to prepare request headers for free endpoint: %v", err)
// 	}

// 	resp, err := client.R().
// 		SetHeaders(headers).
// 		Get(url)

// 	if err != nil {
// 		log.Fatalf("Failed to call free endpoint: %v", err)
// 	}

// 	log.Printf("← HTTP %d: %s", resp.StatusCode(), resp.String())
// }

// func requestPremium(ctx context.Context, wallet wallet.Interface, auth *auth.AuthMessage) *payment.PaymentTerms {
// 	client := resty.New()
// 	url := serverURL + "/premium"

// 	requestData := utils.RequestData{
// 		Method: http.MethodGet,
// 		URL:    url,
// 	}

// 	headers, err := utils.PrepareGeneralRequestHeaders(ctx, wallet, auth, requestData)
// 	if err != nil {
// 		log.Fatalf("Failed to prepare request headers for premium request: %v", err)
// 	}

// 	var terms payment.PaymentTerms
// 	var errMsg any

// 	resp, err := client.R().
// 		SetHeaders(headers).
// 		SetError(&errMsg).
// 		Get(url)

// 	if err != nil {
// 		log.Fatalf("Failed to request premium endpoint: %v", err)
// 	}

// 	if resp.StatusCode() != http.StatusPaymentRequired {
// 		log.Fatalf("Expected status %d for premium request, got %d. Body: %s",
// 			http.StatusPaymentRequired, resp.StatusCode(), resp.String())
// 	}

// 	err = json.Unmarshal(resp.Body(), &terms)
// 	if err != nil {
// 		log.Fatalf("Failed to unmarshal payment terms (402 response): %v. Body: %s", err, resp.String())
// 	}

// 	return &terms
// }

// func createMockPayment(terms *payment.PaymentTerms) *payment.Payment {
// 	suffix := "client-" + time.Now().Format("20060102150405")
// 	mockTx := []byte{0x01, 0x02, 0x03, 0x04}

// 	return &payment.Payment{
// 		ModeID:           "bsv-direct",
// 		DerivationPrefix: terms.DerivationPrefix,
// 		DerivationSuffix: suffix,
// 		Transaction:      mockTx,
// 	}
// }

// func payPremium(ctx context.Context, wallet wallet.Interface, auth *auth.AuthMessage, pmt *payment.Payment) {
// 	client := resty.New()
// 	url := serverURL + "/premium"

// 	paymentData, err := json.Marshal(pmt)
// 	if err != nil {
// 		log.Fatalf("Failed to marshal payment data for header: %v", err)
// 	}

// 	requestData := utils.RequestData{
// 		Method: http.MethodGet,
// 		URL:    url,
// 		Headers: map[string]string{
// 			payment.HeaderPayment: string(paymentData),
// 		},
// 	}

// 	generalHeaders, err := utils.PrepareGeneralRequestHeaders(ctx, wallet, auth, requestData)
// 	if err != nil {
// 		log.Fatalf("Failed to prepare request headers for paying premium: %v", err)
// 	}

// 	var errMsg any

// 	resp, err := client.R().
// 		SetHeaders(generalHeaders).
// 		SetHeader(payment.HeaderPayment, string(paymentData)).
// 		SetError(&errMsg).
// 		Get(url)

// 	if err != nil {
// 		log.Fatalf("Failed to pay premium endpoint: %v", err)
// 	}

// 	log.Printf("← HTTP %d: %s", resp.StatusCode(), resp.String())

// 	if resp.IsError() {
// 		log.Printf("Warning: Received non-success status %d after payment", resp.StatusCode())
// 	}

// 	if sat := resp.Header().Get(payment.HeaderSatoshisPaid); sat != "" {
// 		log.Printf("← Confirmed: %s satoshis paid", sat)
// 	} else if resp.IsSuccess() {
// 		log.Printf("Warning: Payment request successful (Status %d), but '%s' header was missing or empty", resp.StatusCode(), payment.HeaderSatoshisPaid)
// 	}
// }
