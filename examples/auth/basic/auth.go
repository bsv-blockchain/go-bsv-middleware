package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/go-resty/resty/v2"
)

func main() {
	fmt.Println("BSV Auth middleware - Demo")
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	sPrivKey, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
	if err != nil {
		panic(err)
	}

	serverMockedWallet := wallet.NewMockWallet(sPrivKey, walletFixtures.DefaultNonces...)
	fmt.Println("✓ Server mockWallet created")

	// Create authentication middleware with:
	// - authentication enabled
	// - custom logger
	// - mocked wallet with predefined nonces
	// - server private key
	opts := auth.Config{
		AllowUnauthenticated: false,
		Logger:               logger,
		Wallet:               serverMockedWallet,
	}
	middleware, err := auth.New(opts)
	if err != nil {
		panic(err)
	}

	fmt.Println("✓ Auth middleware created")

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

	fmt.Println("✓ HTTP Server started")

	// Create mocked client wallet with predefined client nonces and client identity key
	cPrivKey, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
	if err != nil {
		panic(err)
	}
	mockedWallet := wallet.NewMockWallet(cPrivKey, walletFixtures.ClientNonces...)
	fmt.Println("✓ Client mockWallet created")

	fmt.Println("\n📡 STEP 1: Sending non general request to /.well-known/auth endpoint")
	responseData := callInitialRequest(mockedWallet)
	fmt.Println("✓ Auth completed")

	fmt.Println("\n📡 STEP 2: Sending general request to test authorization")
	callPingEndpoint(mockedWallet, responseData)
	fmt.Println("✓ General request completed")
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Pong!"))
	if err != nil {
		log.Printf("Error writing ping response: %v", err)
	}
}

func callInitialRequest(mockedWallet wallet.WalletInterface) *transport.AuthMessage {
	requestData := utils.PrepareInitialRequestBody(mockedWallet)
	url := "http://localhost:8080/.well-known/auth"

	client := resty.New()
	var result transport.AuthMessage
	var errMsg any

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

func callPingEndpoint(mockedWallet wallet.WalletInterface, response *transport.AuthMessage) {
	url := "http://localhost:8080/ping"

	requestData := utils.RequestData{
		Method: http.MethodGet,
		URL:    url,
	}
	headers, err := utils.PrepareGeneralRequestHeaders(mockedWallet, response, requestData)
	if err != nil {
		log.Fatalf("Failed to prepare general request headers: %v", err)
	}

	fmt.Println("🔑 Request headers")
	for key, value := range headers {
		fmt.Println(key, value)
	}

	client := resty.New()
	resp, err := client.R().
		SetHeaders(headers).
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
}
