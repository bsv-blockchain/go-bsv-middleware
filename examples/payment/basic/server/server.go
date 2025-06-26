package main

// TODO: Adjust example to use client from go-sdk

// import (
// 	"errors"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"os"
// 	"os/signal"
// 	"syscall"

// 	wallet "github.com/bsv-blockchain/go-bsv-middleware-examples/example-wallet"
// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/payment"
// 	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
// )

// const (
// 	serverPrivateKeyHex = "5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef"
// 	clientPrivateKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
// 	serverPort          = ":8080"
// 	trustedCertifier    = "02certifieridentitykey00000000000000000000000000000000000000000000000"
// )

// func main() {
// 	log.Println("Starting BSV Payment Server")

// 	sPrivKey, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)
// 	if err != nil {
// 		log.Fatalf("Failed to parse server private key: %v", err)
// 	}

// 	paymentWallet, err := wallet.NewExtendedProtoWallet(sPrivKey)
// 	if err != nil {
// 		log.Fatalf("Failed to create wallet: %v", err)
// 	}
// 	log.Println("Wallet created successfully")

// 	authMiddleware, err := auth.New(auth.Config{
// 		AllowUnauthenticated: false,
// 		Wallet:               paymentWallet,
// 	})
// 	if err != nil {
// 		log.Fatalf("Failed to create auth middleware: %v", err)
// 	}
// 	log.Println("Auth middleware initialized")

// 	paymentMiddleware, err := payment.New(payment.Options{
// 		Wallet: paymentWallet,
// 		CalculateRequestPrice: func(r *http.Request) (int, error) {
// 			switch r.URL.Path {
// 			case "/info":
// 				return 0, nil
// 			case "/premium":
// 				return 10, nil
// 			default:
// 				return 5, nil
// 			}
// 		},
// 	})
// 	if err != nil {
// 		log.Fatalf("Failed to create payment middleware: %v", err)
// 	}
// 	log.Println("Payment middleware initialized")

// 	mux := http.NewServeMux()
// 	mux.HandleFunc("/info", infoHandler)
// 	mux.HandleFunc("/premium", premiumHandler)

// 	handler := authMiddleware.Handler(paymentMiddleware.Handler(mux))

// 	srv := &http.Server{
// 		Addr:    serverPort,
// 		Handler: handler,
// 	}

// 	go func() {
// 		log.Printf("Server listening on %s", srv.Addr)
// 		log.Println("Available endpoints:")
// 		log.Println("  /.well-known/auth")
// 		log.Println("  /info (auth only)")
// 		log.Println("  /premium (auth + payment)")

// 		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
// 			log.Printf("Server error: %v", err)
// 		}
// 	}()

// 	quit := make(chan os.Signal, 1)
// 	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
// 	<-quit

// 	log.Println("Server shutting down...")
// }

// func infoHandler(w http.ResponseWriter, r *http.Request) {
// 	log.Printf("GET %s from %s", r.URL.Path, r.RemoteAddr)

// 	w.Header().Set("Content-Type", "application/json")
// 	response := `{"name":"BSV Payment API","version":"1.0","type":"free"}`

// 	if _, err := w.Write([]byte(response)); err != nil {
// 		log.Printf("Error writing response: %v", err)
// 		return
// 	}
// }

// func premiumHandler(w http.ResponseWriter, r *http.Request) {
// 	log.Printf("GET %s from %s", r.URL.Path, r.RemoteAddr)

// 	info, ok := payment.GetPaymentInfoFromContext(r.Context())
// 	w.Header().Set("Content-Type", "application/json")

// 	if ok && info.SatoshisPaid > 0 {
// 		log.Printf("Payment verified: %d satoshis, txid: %s", info.SatoshisPaid, info.TransactionID)

// 		response := fmt.Sprintf(`{
//             "name": "BSV Payment API",
//             "version": "1.0",
//             "type": "premium",
//             "paid": true,
//             "satoshis": %d,
//             "status": "Payment accepted",
//             "txid": "%s"
//         }`, info.SatoshisPaid, info.TransactionID)

// 		if _, err := w.Write([]byte(response)); err != nil {
// 			log.Printf("Error writing response: %v", err)
// 			return
// 		}
// 		return
// 	}

// 	// NOTE: This code path is for demonstration only and won't actually execute
// 	// in normal operation because the payment middleware would intercept the request
// 	// with a 402 Payment Required response before reaching this handler
// 	log.Println("WARNING: Premium endpoint reached without payment - this should not happen")

// 	response := `{
//         "name": "BSV Payment API",
//         "version": "1.0",
//         "type": "premium",
//         "paid": false,
//         "note": "This code path would normally not be reached - middleware would return 402 Payment Required"
//     }`

// 	if _, err := w.Write([]byte(response)); err != nil {
// 		log.Printf("Error writing response: %v", err)
// 		return
// 	}
// }
