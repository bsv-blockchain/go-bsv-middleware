package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/examples/utils"
	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

func main() {
	// Create structured logger
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	// Create authentication middleware with:
	// - authentication enabled
	// - custom logger
	// - mocked wallet with predefined nonces
	opts := auth.Options{
		AllowUnauthenticated: false,
		Logger:               logger,
		Wallet:               wallet.NewMockWallet(true, nil, walletFixtures.DefaultNonces...),
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

	// Call /ping endpoint with set up auth headers
	callPingEndpoint(mockedWallet, responseData)
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Pong!"))
}

func callInitialRequest(mockedWallet wallet.WalletInterface) *transport.AuthMessage {
	requestData := utils.PrepareInitialRequest(mockedWallet)
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
		fmt.Println("[EXAMPLE] Header:               ", key, value)
	}

	fmt.Println()
	fmt.Println()

	return responseData
}

func callPingEndpoint(mockedWallet wallet.WalletInterface, response *transport.AuthMessage) {
	url := "http://localhost:8080/ping"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	utils.PreparePingRequest(req, mockedWallet, response)

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
		fmt.Println("[EXAMPLE] Header:           ", key, value)
	}
}
