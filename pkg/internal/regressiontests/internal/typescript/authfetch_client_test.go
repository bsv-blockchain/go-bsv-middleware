package typescript_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/regressiontests/internal/typescript"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/testabilities/testusers"
)

// TestAuthFetchClientCallForDevelopmentPurposes this test is used for developing bridge between Go and Typescript
// For development phase, feel free to comment out t.Skip and run it (or extend)
// To make it working, you need to:
// 1. run typescript grpc server - see README.md
// 2. run some Go server (you can use examples/auth/auth_basic_server/auth_basic_server_main.go)
// 3. run this test
func TestAuthFetchClientCallForDevelopmentPurposes(t *testing.T) {
	t.Skip("used for auth fetch client development purposes")

	client, cleanup := typescript.NewAuthFetch(wallet.PrivHex(testusers.Alice.PrivKey))
	defer cleanup()

	url := "http://localhost:8888/post"
	config := &clients.SimplifiedFetchRequestOptions{
		Method: http.MethodPost,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: []byte(`{"ping": true}`),
	}
	resp, err := client.Fetch(t.Context(), url, config)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	printCommunication(url, config, resp)

	t.Log(strings.Repeat("~", 40))
	t.Log("Second request with the same client")
	url = "http://localhost:8888/get"
	config = &clients.SimplifiedFetchRequestOptions{
		Method: http.MethodGet,
		Headers: map[string]string{
			"X-BSV-TEST": "true",
		},
	}
	resp, err = client.Fetch(t.Context(), url, config)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	printCommunication(url, config, resp)
}

//nolint:forbidigo // development/debugging utility function
func printCommunication(url string, config *clients.SimplifiedFetchRequestOptions, resp *http.Response) {
	fmt.Println("=============== Request ===============")
	fmt.Println()
	fmt.Printf("Status: %s %s\n", config.Method, url)
	fmt.Println()
	fmt.Println("Headers:")
	fmt.Println()
	for key, value := range config.Headers {
		fmt.Printf("%s: %s\n", key, value)
	}
	fmt.Println()
	fmt.Println("Body:")
	fmt.Println()
	fmt.Println(string(config.Body))
	fmt.Println()
	fmt.Println("=============== Response ===============")
	fmt.Println()
	fmt.Printf("%d %s\n", resp.StatusCode, resp.Status)
	fmt.Println()
	fmt.Println("Headers:")
	fmt.Println()
	for key, value := range resp.Header {
		fmt.Printf("%s: %s\n", key, value)
	}
	fmt.Println()
	fmt.Println("Body:")
	fmt.Println()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("<error reading body:", err, ">")
	} else {
		fmt.Println(string(body))
	}
	fmt.Println()
	fmt.Println("========================================")
}
