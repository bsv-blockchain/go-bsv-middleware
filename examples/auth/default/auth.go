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

	// Create authentication middleware
	opts := auth.Options{
		AllowUnauthenticated: false,
		Logger:               logger,
		Wallet:               wallet.NewMockWallet(true, nil, walletFixtures.DefaultNonces...),
	}
	middleware := auth.New(opts)

	// Define HTTP server and handlers
	mux := http.NewServeMux()
	mux.Handle("/", middleware.Handler(http.HandlerFunc(helloHandler)))
	mux.Handle("/ping", middleware.Handler(http.HandlerFunc(pingHandler)))

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Server started", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", slog.Any("error", err))
		}
	}()

	// Wait briefly to ensure the server is running before sending the request
	time.Sleep(1 * time.Second)

	// Create mocked wallet
	mockedWallet := wallet.NewMockWallet(true, &walletFixtures.ClientIdentityKey, walletFixtures.ClientNonces...)

	// Send initial request
	response := callInitialRequest(mockedWallet)

	// Call ping endpoint
	callPingEndpoint(mockedWallet, response)

	// Block main thread
	select {}
}

// Handlers
func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello, World!")
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	identity := r.Context().Value(transport.IdentityKey).(string)
	fmt.Println(w, "Authorized!")
	fmt.Println("[EXAMPLE] Identity key:             ", identity)
}

// Request functions
func callInitialRequest(mockedWallet wallet.Interface) *transport.AuthMessage {
	initialRequest := utils.PrepareInitialRequest(mockedWallet)
	jsonData, err := json.Marshal(initialRequest)
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

	log.Printf("Response from server: %s", string(body))

	var response *transport.AuthMessage
	if err = json.Unmarshal(body, &response); err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}

	fmt.Println("[EXAMPLE] Response signature:", *response.Signature)
	return response
}

func callPingEndpoint(mockedWallet wallet.Interface, response *transport.AuthMessage) {
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

	log.Printf("Response from server: %s", string(body))
}
