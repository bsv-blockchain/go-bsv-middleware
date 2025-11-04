package typescript

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-softwarelab/common/pkg/must"
	"github.com/go-softwarelab/common/pkg/slogx"
	"github.com/go-softwarelab/common/pkg/to"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AuthFetchClientOptions struct {
	host   string
	port   string
	logger *slog.Logger
}

func WithHost(host string) func(*AuthFetchClientOptions) {
	return func(options *AuthFetchClientOptions) {
		options.host = host
	}
}

func WithPort(port int) func(*AuthFetchClientOptions) {
	return func(options *AuthFetchClientOptions) {
		options.port = to.StringFromInteger(port)
	}
}

func WithLogger(logger *slog.Logger) func(*AuthFetchClientOptions) {
	return func(options *AuthFetchClientOptions) {
		options.logger = logger
	}
}

// AuthFetch is a client for a grpc server providing TypeScript AuthFetch functionality.
type AuthFetch struct {
	id         string
	client     AuthFetchClient
	logger     *slog.Logger
	privKeyHex string
}

// NewAuthFetch creates a new AuthFetch
func NewAuthFetch[PrivKeySource wallet.PrivateKeySource](privKeySource PrivKeySource, opts ...func(*AuthFetchClientOptions)) (client *AuthFetch, cleanup func()) {
	priv, err := wallet.ToPrivateKey(privKeySource)
	if err != nil {
		panic("invalid private key passed" + err.Error())
	}
	privKeyHex := priv.Hex()

	options := to.OptionsWithDefault(AuthFetchClientOptions{
		host: "localhost",
		port: "50050",
	}, opts...)

	conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", options.host, options.port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic("failed to instantiate grpc client:" + err.Error())
	}

	id := rand.Text()

	fetchClient := NewAuthFetchClient(conn)

	logger := slogx.Child(options.logger, "AuthFetchClient")

	cleanup = func() {
		if _, err := fetchClient.CleanUp(context.Background(), &CleanUpRequest{ClientId: id}); err != nil {
			logger.Error("Failed to clean up the client on gRPC server")
		}

		if err := conn.Close(); err != nil {
			logger.Error("Failed to close the gRPC connection")
		}
	}

	return &AuthFetch{
		id:         id,
		privKeyHex: privKeyHex,
		client:     fetchClient,
		logger:     logger,
	}, cleanup
}

// Fetch forwards the call to the underlying generated client.
func (a *AuthFetch) Fetch(ctx context.Context, url string, config *clients.SimplifiedFetchRequestOptions) (*http.Response, error) {
	retryCounter := must.ConvertToInt32(to.Value(config.RetryCounter))

	response, err := a.client.Fetch(ctx, &FetchRequest{
		Url: url,
		Config: &Config{
			Method:       config.Method,
			Headers:      config.Headers,
			Body:         string(config.Body),
			RetryCounter: retryCounter,
		},
		Options: &Options{
			ClientId:   a.id,
			PrivKeyHex: a.privKeyHex,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("AuthFetchClient.Fetch() failed on gRPC call:\n\t %w", err)
	}

	result := &http.Response{
		StatusCode: int(response.GetStatus()),
		Body:       io.NopCloser(strings.NewReader(response.GetBody())),
		Header:     make(http.Header),
	}

	for key, value := range response.GetHeaders() {
		result.Header.Set(key, value)
	}

	return result, nil
}
