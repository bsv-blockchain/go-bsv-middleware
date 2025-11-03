package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/bsv-blockchain/go-bsv-middleware/examples/internal/example_wallet"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
)

const (
	serverWIF     = "L1cReZseWmqcYra3vrqj9TPBGHhvDQFD2jYuu1RUj5rrfpVLiKHs"
	clientPrivHex = "143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c"
)

func main() {
	// ===============================================================================================
	// First start a server with the auth middleware.
	// ===============================================================================================

	// serverWallet - The wallet here is tweaked for example purposes.
	// For a real-world application, you should use
	// - a wallet implementation from github.com/bsv-blockchain/go-wallet-toolbox package
	// - a wallet client provided by github.com/bsv-blockchain/go-sdk package
	// - or any custom wallet implementation you have.
	serverWallet := example_wallet.New(example_wallet.WIF(serverWIF))

	authMiddleware := middleware.NewAuth(serverWallet)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Pong!"))
		if err != nil {
			panic(err)
		}
	})

	server := http.Server{
		Addr:    ":8888",
		Handler: authMiddleware.HTTPHandler(mux),
	}

	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server error", "error", err)
			os.Exit(1)
		}
	}()

	// ===============================================================================================
	// Now make a request to the server.
	// ===============================================================================================

	clientWallet := example_wallet.New(example_wallet.PrivHex(clientPrivHex))

	fetch := clients.New(clientWallet)

	response, err := fetch.Fetch(context.Background(), "http://localhost:8888", nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("=============== Response ==========================")
	err = response.Write(os.Stdout)
	if err != nil {
		panic(err)
	}
	fmt.Println()
	fmt.Println("==================================================")

	// Graceful shutdown
	if err := server.Shutdown(context.Background()); err != nil {
		slog.Error("Error during server shutdown", "error", err)
	}
}
