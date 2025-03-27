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

	ginadapter "github.com/4chain-ag/go-bsv-middleware/adapter/gin"
	"github.com/4chain-ag/go-bsv-middleware/examples/utils"
	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/gin-gonic/gin"
)

func main() {
	// Create structured logger
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	// Initialize Gin router
	router := gin.Default()

	// Create authentication middleware
	opts := auth.Options{
		AllowUnauthenticated: false,
		Logger:               logger,
		Wallet:               wallet.NewMockWallet(true, walletFixtures.DefaultNonces...),
	}

	ginMiddleware := ginadapter.AuthMiddleware(opts)

	// Apply authentication middleware
	router.Use(ginMiddleware)

	// Register routes
	router.GET("/", helloHandler)
	router.GET("/ping", pingHandler)

	// Start the server in a goroutine
	addr := ":8080"
	go func() {
		logger.Info("Server started", slog.String("addr", addr))
		if err := router.Run(addr); err != nil {
			logger.Error("Server failed", slog.Any("error", err))
		}
	}()

	// Wait briefly to ensure the server is running before sending the request
	time.Sleep(1 * time.Second)

	// Create mocked wallet
	mockedWallet := wallet.NewMockWallet(true, walletFixtures.ClientNonces...)

	// Send initial request
	response := callInitialRequest(mockedWallet)

	// Call ping endpoint
	callPingEndpoint(mockedWallet, response)

	// Block main thread (so the server keeps running)
	select {}
}

// helloHandler responds with "Hello, World!"
func helloHandler(c *gin.Context) {
	c.String(http.StatusOK, "Hello, World!")
}

// pingHandler responds with "Authorized!"
func pingHandler(c *gin.Context) {
	c.String(http.StatusOK, "Authorized!")
}

func callInitialRequest(mockedWallet wallet.Interface) *transport.AuthMessage {
	// Prepare initial request
	initialRequest := utils.PrepareInitialRequest(mockedWallet)

	jsonData, err := json.Marshal(initialRequest)
	if err != nil {
		log.Fatalf("Failed to marshal request: %v", err)
	}

	// Send initial request
	url := "http://localhost:8080/.well-known/auth"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	log.Printf("Response from server: %s", string(body))

	// Unmarshal response
	var response *transport.AuthMessage
	if err = json.Unmarshal(body, &response); err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}

	fmt.Println("[EXAMPLE]  Response signature:  ", *response.Signature)

	return response
}

func callPingEndpoint(mockedWallet wallet.Interface, response *transport.AuthMessage) {
	// Prepare request
	url := "http://localhost:8080/ping"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	utils.PreparePingRequest(req, mockedWallet, response)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	log.Printf("Response from server: %s", string(body))

}
