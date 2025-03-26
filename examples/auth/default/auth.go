package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func main() {
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	mux := http.NewServeMux()

	opts := auth.Options{
		AllowUnauthenticated: false,
		Logger:               logger,
	}
	middleware := auth.New(opts)

	mux.Handle("/", http.HandlerFunc(helloHandler))

	handler := middleware.Handler(mux)

	server := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}

	log.Println("Server started on :8080")
	log.Fatal(server.ListenAndServe())
}
