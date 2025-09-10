# Basic Authenticated Request (Server + Client in one process)

This example demonstrates how to protect an HTTP server with the BSV Auth middleware and how to call it using the Go auth HTTP client. Both the server and the client are started within a single Go process for simplicity.

## Overview

The flow:
1. Start an HTTP server on :8888 wrapped by the Auth middleware.
2. Expose a single route ("/") that returns the text "Pong!".
3. Create an authenticated HTTP client backed by a wallet implementation.
4. Perform a request to the server and print the raw HTTP response to stdout.
5. Gracefully shut down the server.

This showcases BRC-103/104 mutual authentication using the go-bsv-middleware and go-sdk libraries.

## Code Walkthrough

### Components
- Auth middleware: github.com/bsv-blockchain/go-bsv-middleware
- Example wallet (for demo only)
- Authenticated HTTP client: clients.AuthFetch from go-sdk

### Configuration Parameters
- serverWIF: WIF string used to initialize the server-side example wallet.
- clientPrivHex: Private key hex used to initialize the client-side example wallet.

## Running the Example

```bash
go run ./examples/auth/auth_basic/auth_basic_main.go
```

## Expected Output

The program prints the raw HTTP response including headers and the body:

```text
=============== Response ==========================
HTTP/1.1 200 OK
Content-Length: 5
Content-Type: text/plain; charset=utf-8
Date: <date>

Pong!
==================================================
```

Note: Exact headers (such as Date) may differ by environment.

## Integration Steps

To integrate the Auth middleware and client in your application:
1. Initialize a production-ready wallet (do not use the example wallet in real systems).
2. Wrap your HTTP handlers with middleware.NewAuth(yourServerWallet).
3. On the client side, use an auth-enabled client (clients.AuthFetch from go-sdk, or compatible clients in other languages).
4. Handle errors and timeouts as appropriate for your environment.
