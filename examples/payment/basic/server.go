package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/payment"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
)

func main() {
	mockWallet := wallet.NewMockPaymentWallet()

	authMiddleware := auth.New(auth.Options{
		Wallet:               mockWallet,
		AllowUnauthenticated: false,
	})

	paymentMiddleware, err := payment.New(payment.Options{
		Wallet: mockWallet,
		CalculateRequestPrice: func(r *http.Request) (int, error) {
			// start with basic 10 satoshis per request
			return 10, nil
		},
	})
	if err != nil {
		log.Fatalf("Failed to create payment middleware: %v", err)
	}

	weatherHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paymentInfo, ok := payment.GetPaymentInfoFromContext(r.Context())
		if ok {
			log.Printf("Request paid: %d satoshis", paymentInfo.SatoshisPaid)
		}

		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"location":"New York","temperature":72,"condition":"Sunny"}`))
		if err != nil {
			return
		}
	})

	infoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"name":"BSV Payment API","version":"1.0","free":true}`))
		if err != nil {
			return
		}
	})

	http.Handle("/weather", authMiddleware.Handler(paymentMiddleware.Handler(weatherHandler)))
	http.Handle("/info", authMiddleware.Handler(infoHandler))

	log.Println("Starting server on :8080")
	log.Println("Endpoints:")
	log.Println("- /weather - Paid endpoint (10 satoshis)")
	log.Println("- /info - Free endpoint (authentication only)")

	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Server shutting down...")
}
