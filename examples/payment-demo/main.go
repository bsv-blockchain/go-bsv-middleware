package payment_demo

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/payment"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"io"
	"log"
	"net/http"
	"time"
)

var (
	mode     = flag.String("mode", "server", "Mode: 'server' or 'client'")
	port     = flag.Int("port", 8080, "Port to listen on (server mode)")
	url      = flag.String("url", "http://localhost:8080", "URL to connect to (client mode)")
	endpoint = flag.String("endpoint", "weather", "Endpoint to call: weather, premium, or forecast")
)

// WeatherResponse represents weather data
type WeatherResponse struct {
	Temperature  float64 `json:"temperature"`
	Condition    string  `json:"condition"`
	Location     string  `json:"location"`
	Premium      bool    `json:"premium,omitempty"`
	SatoshisPaid int     `json:"satoshisPaid"`
}

// ForecastDay represents forecast for a single day
type ForecastDay struct {
	Day         string  `json:"day"`
	Temperature float64 `json:"temperature"`
	Condition   string  `json:"condition"`
}

// ForecastResponse represents forecast data
type ForecastResponse struct {
	Days         []ForecastDay `json:"days"`
	SatoshisPaid int           `json:"satoshisPaid"`
}

// Add auth middleware "mock" for testing purposes
func mockAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityKey := r.Header.Get("X-Test-Identity-Key")
		if identityKey == "" {
			identityKey = "basic-test-identity"
		}

		ctx := context.WithValue(r.Context(), transport.IdentityKey, identityKey)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func runServer() {
	log.Println("Starting server on port", *port)

	servWallet := wallet.NewMockPaymentWallet()

	paymentMiddleware, err := payment.New(payment.Options{
		Wallet: servWallet,
		CalculateRequestPrice: func(r *http.Request) (int, error) {
			switch r.URL.Path {
			case "/api/weather":
				return 0, nil // Free
			case "/api/premium":
				return 500, nil // Premium costs 500 satoshis
			case "/api/forecast":
				return 100, nil // Forecast costs 100 satoshis
			default:
				return 50, nil // Default price
			}
		},
	})
	if err != nil {
		log.Fatalf("Failed to create payment middleware: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/weather", func(w http.ResponseWriter, r *http.Request) {
		identityKey, _ := auth.GetIdentityFromContext(r.Context())
		log.Printf("Weather endpoint accessed by %s", identityKey)

		info, _ := payment.GetPaymentInfoFromContext(r.Context())

		w.Header().Set("Content-Type", "application/json")
		response := WeatherResponse{
			Temperature:  22.5,
			Condition:    "Sunny",
			Location:     "New York",
			SatoshisPaid: info.SatoshisPaid,
		}
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			return
		}
	})

	mux.HandleFunc("/api/premium", func(w http.ResponseWriter, r *http.Request) {
		identityKey, _ := auth.GetIdentityFromContext(r.Context())
		log.Printf("Premium endpoint accessed by %s", identityKey)

		info, _ := payment.GetPaymentInfoFromContext(r.Context())

		w.Header().Set("Content-Type", "application/json")
		response := WeatherResponse{
			Temperature:  23.8,
			Condition:    "Partly Cloudy",
			Location:     "New York",
			Premium:      true,
			SatoshisPaid: info.SatoshisPaid,
		}
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			return
		}
	})

	mux.HandleFunc("/api/forecast", func(w http.ResponseWriter, r *http.Request) {
		identityKey, _ := auth.GetIdentityFromContext(r.Context())
		log.Printf("Forecast endpoint accessed by %s", identityKey)

		info, _ := payment.GetPaymentInfoFromContext(r.Context())

		w.Header().Set("Content-Type", "application/json")
		response := ForecastResponse{
			Days: []ForecastDay{
				{Day: "Monday", Temperature: 24.0, Condition: "Sunny"},
				{Day: "Tuesday", Temperature: 22.5, Condition: "Partly Cloudy"},
				{Day: "Wednesday", Temperature: 21.0, Condition: "Rain"},
			},
			SatoshisPaid: info.SatoshisPaid,
		}
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			return
		}
	})

	handler := mockAuthMiddleware(paymentMiddleware.Handler(mux))

	addr := fmt.Sprintf(":%d", *port)
	log.Println("Server started on port", *port)
	log.Println("Available endpoints:")
	log.Println("  - /api/weather (Free)")
	log.Println("  - /api/premium (500 satoshis)")
	log.Println("  - /api/forecast (100 satoshis)")
	log.Fatal(http.ListenAndServe(addr, handler))
}

func runClient() {
	// Will be needed for auth middleware
	//clientWallet := wallet.NewMockPaymentWallet()

	var apiPath string
	switch *endpoint {
	case "weather":
		apiPath = "/api/weather"
	case "premium":
		apiPath = "/api/premium"
	case "forecast":
		apiPath = "/api/forecast"
	default:
		log.Fatalf("Unknown endpoint: %s", *endpoint)
	}

	log.Printf("Making request to %s%s", *url, apiPath)

	req, err := http.NewRequest("GET", *url+apiPath, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("X-Test-Identity-Key", "client-identity-key-123")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode == http.StatusPaymentRequired {
		price := resp.Header.Get("X-BSV-Payment-Satoshis-Required")
		derivationPrefix := resp.Header.Get("X-BSV-Payment-Derivation-Prefix")

		log.Printf("Payment required: %s satoshis with prefix %s", price, derivationPrefix)

		derivationSuffix := "client-suffix-" + fmt.Sprintf("%d", time.Now().UnixNano())
		mockTx := []byte{0x01, 0x02, 0x03, 0x04}

		paymentData := struct {
			DerivationPrefix string `json:"derivationPrefix"`
			DerivationSuffix string `json:"derivationSuffix"`
			Transaction      []byte `json:"transaction"`
		}{
			DerivationPrefix: derivationPrefix,
			DerivationSuffix: derivationSuffix,
			Transaction:      mockTx,
		}

		paymentJSON, err := json.Marshal(paymentData)
		if err != nil {
			log.Fatalf("Failed to marshal payment data: %v", err)
		}

		req, err = http.NewRequest("GET", *url+apiPath, nil)
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		req.Header.Set("X-Test-Identity-Key", "client-identity-key-123")
		req.Header.Set("X-BSV-Payment", string(paymentJSON))

		resp, err = client.Do(req)
		if err != nil {
			log.Fatalf("Request with payment failed: %v", err)
		}
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	log.Printf("Response status: %d", resp.StatusCode)
	for k, v := range resp.Header {
		if k == "X-Bsv-Payment-Satoshis-Paid" {
			log.Printf("Header %s: %s", k, v[0])
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err == nil {
		prettyJSON, _ := json.MarshalIndent(data, "", "  ")
		log.Printf("Response:\n%s", string(prettyJSON))
	} else {
		log.Printf("Response body: %s", string(body))
	}
}

func main() {
	flag.Parse()

	switch *mode {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		log.Fatalf("Unknown mode: %s. Use 'server' or 'client'", *mode)
	}
}
