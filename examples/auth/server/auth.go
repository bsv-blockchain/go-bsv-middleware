package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	exampleWallet "github.com/bsv-blockchain/go-bsv-middleware/examples/example-wallet"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

const serverWIF = "L1cReZseWmqcYra3vrqj9TPBGHhvDQFD2jYuu1RUj5rrfpVLiKHs"

func main() {
	key, err := primitives.PrivateKeyFromWif(serverWIF)
	if err != nil {
		panic(err)
	}

	wallet, err := exampleWallet.NewExtendedProtoWallet(key)
	if err != nil {
		panic(err)
	}

	authMiddleware, err := auth.New(auth.Config{
		AllowUnauthenticated: false,
		Wallet:               wallet,
		Logger:               slog.Default(),
	})
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /ping", func(w http.ResponseWriter, r *http.Request) {
		bytes, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Error reading request body", "error", err)
		}

		response := map[string]string{
			"method": r.Method,
			"query":  r.URL.RawQuery,
			"body":   string(bytes),
		}

		for hKey, hValue := range r.Header {
			response[hKey] = hValue[0]
		}

		responseBody, err := json.Marshal(response)
		if err != nil {
			slog.Error("Error marshaling response body", "error", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(responseBody)
		if err != nil {
			slog.Error("Error writing response body", "error", err)
			return
		}
	})

	server := http.Server{
		Addr:    ":8888",
		Handler: authMiddleware.Handler(mux),
	}

	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server error", "error", err)
			os.Exit(1)
		}
	}()

	// Create channel for shutdown signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Create channel for user input
	userInput := make(chan struct{})
	go func() {
		fmt.Println("Press Enter to shutdown the server... ")
		// ignoring the errors, because we want to just hang and wait for any input
		fmt.Scanln()
		userInput <- struct{}{}
	}()

	// Wait for either shutdown signal or user input
	select {
	case <-stop:
		slog.Info("Shutting down server due to signal...")
	case <-userInput:
		slog.Info("Shutting down server due to user input...")
	}

	// Graceful shutdown
	if err := server.Shutdown(context.Background()); err != nil {
		slog.Error("Error during server shutdown", "error", err)
	}
}
