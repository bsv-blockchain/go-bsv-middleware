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
	"time"

	"github.com/bsv-blockchain/go-bsv-middleware/examples/internal/example_wallet"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
)

const serverWIF = "L1cReZseWmqcYra3vrqj9TPBGHhvDQFD2jYuu1RUj5rrfpVLiKHs"

func main() {
	// The wallet here is tweaked for example purposes.
	// For a real-world application, you should use
	// - a wallet implementation from github.com/bsv-blockchain/go-wallet-toolbox package
	// - a wallet client provided by github.com/bsv-blockchain/go-sdk package
	// - or any custom wallet implementation you have.
	serverWallet := example_wallet.New(example_wallet.WIF(serverWIF))

	authMiddleware := middleware.NewAuth(serverWallet)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handlerEchoingRequest())

	server := http.Server{
		Addr: ":8888",
		Handler: &AllowAllCORSHandler{
			Next: authMiddleware.HTTPHandler(mux),
		},
		ReadHeaderTimeout: 10 * time.Second,
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
		slog.Info("Press Enter to shutdown the server... ")
		// ignoring the errors, because we want to just hang and wait for any input
		var input string
		_, _ = fmt.Fscanln(os.Stdin, &input)
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

func handlerEchoingRequest() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bytes, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Error reading request body", "error", err)
		}

		response := map[string]string{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
			"body":   string(bytes),
		}

		for hKey, hValue := range r.Header {
			if len(hValue) > 0 {
				response[hKey] = hValue[0]
			}
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
	}
}

// AllowAllCORSHandler Such a middleware is needed before auth middleware to handle requests from browsers.
type AllowAllCORSHandler struct {
	Next http.Handler
}

func (h *AllowAllCORSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Expose-Headers", "*")
	w.Header().Set("Access-Control-Allow-Private-Network", "true")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	h.Next.ServeHTTP(w, r)
}
