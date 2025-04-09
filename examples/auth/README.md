# BSV Authentication Examples

This directory contains examples demonstrating how to use the BSV authentication middleware for implementing BRC-103/104 mutual authentication in Go applications.

## Overview

The examples showcase different authentication scenarios using the `go-bsv-middleware` library:

1. **Basic Authentication** - Simple mutual authentication flow
2. **Certificate Authentication** - Advanced authentication with certificate verification

## Requirements

- Go 1.24 or higher
- The `go-bsv-middleware` package and its dependencies

## Basic Authentication Example

The basic example demonstrates a simple authentication flow between a client and server:

```
examples/auth/basic/
```

### Running the Basic Example

```bash
cd auth/basic
go run auth.go
```

This example shows:
- Server setup with authentication middleware
- Client authentication handshake
- Sending authenticated requests to protected endpoints

### Authentication Flow

1. Client initiates authentication by sending an `initialRequest` to `/.well-known/auth`
2. Server responds with `initialResponse` containing its identity key and a session nonce
3. Client sends a regular request with authentication headers
4. Server validates the request and responds with authenticated content

## Certificate Authentication Example

The certificate example demonstrates a more advanced authentication flow with certificate verification:

```
examples/auth/certificate/
```

### Running the Certificate Example

```bash
cd auth/certificate
go run certificate.go
```

This example shows:
- Age verification using certificates
- Server requesting specific certificates from clients
- Certificate submission and validation
- Access control based on certificate contents

### Certificate Flow

1. Server is configured to require age verification certificates
2. Client initiates authentication handshake
3. Server responds with certificate requirements
4. Client attempts access without certificate (denied)
5. Client submits age verification certificate
6. Server validates certificate contents (age ≥ 18)
7. Client gains access to protected resources

## Implementation Details

### Server Setup

```go
// Configure authentication middleware
opts := auth.Config{
    AllowUnauthenticated: false,
    Logger:               logger,
    Wallet:               wallet.NewMockWallet(true, nil),
    // Specify which types of certificates and which certifiers we want to check
    CertificatesToRequest: &certificateToRequest := transport.RequestedCertificateSet{
            Certifiers: []string{trustedCertifier},
            Types: map[string][]string{
                "age-verification": {"age"},
            },
        },
    // Specify function you want to use to verify certificate fields
    OnCertificatesReceived: 	onCertificatesReceived := func(
		senderPublicKey string,
		certs *[]wallet.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func()) {
            validAge = false
            ...
            // Do additional checks
            ...
			// Extract and parse age
            ...
			// Validate age
			if age < 18 {
				logger.Error("Age below 18", slog.Int("age", age))
			}
            ...
			logger.Info("Age verified", slog.Int("age", age))
			validAge = true
			return
            ...
		}
}
middleware := auth.New(opts)

mux := http.NewServeMux()
mux.Handle("/ping", middleware.Handler(http.HandlerFunc(pingHandler)))
```

### Client Authentication

```go
// 1. Initial handshake
initialRequest := utils.PrepareInitialRequestBody(clientWallet)
response := sendRequest("/.well-known/auth", initialRequest)

// 2. Regular requests with auth headers
headers := utils.PrepareGeneralRequestHeaders(clientWallet, response, "/ping", "GET")
authenticatedResponse := sendRequestWithHeaders("/ping", "GET", headers)
```

## Key Concepts

- **BRC-103/104**: Bitcoin SV Peer-to-Peer Mutual Authentication protocol
- **Wallet Interface**: Used for cryptographic operations (signing, verification)
- **Session Management**: Tracks authenticated sessions between requests
- **Certificate Exchange**: Optional verification of client attributes

## Additional Resources

- The middleware implements [BRC-103](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0103.md) and [BRC-104](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0104.md) specifications
