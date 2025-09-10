# Auth-Enabled HTTP Server (Standalone)

This example shows how to run a standalone HTTP server protected by the BSV Auth middleware. The server responds by echoing request details as JSON and enables permissive CORS to make browser testing easy.

## Overview

The flow:
1. Initialize an example wallet and create the Auth middleware.
2. Build an http.ServeMux and register the root handler that echoes request info.
3. Wrap the mux with a CORS handler and the Auth middleware.
   - Notice: Handler chain: AllowAllCORSHandler -> Auth middleware -> ServeMux.  
4. Start the server on :8888 and wait until the user presses Enter or sends a termination signal.

This demonstrates where the Auth middleware fits in a real server, handling BRC-103/104 authentication for incoming requests.

## Code Walkthrough

### Components
- Auth middleware: github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware
- Example wallet (for demo only): github.com/bsv-blockchain/go-bsv-middleware/examples/internal/example_wallet
- CORS wrapper: a simple AllowAllCORSHandler placed before the Auth middleware - allowing browser clients to make authenticated requests.

### Configuration Parameters
- serverWIF: WIF for initializing the server-side example wallet.

## Running the Example

```bash
go run ./examples/auth/auth_basic_server/auth_basic_server_main.go
```

You should see a prompt:

```text
Press Enter to shutdown the server...
```

In a separate terminal, use any BRC-103/104-capable client (for example, the Go auth HTTP client from go-sdk) to perform an authenticated request to:

```
http://localhost:8888
```

Note: A plain curl without authentication will typically be rejected by the Auth middleware.

## Integration Steps

To integrate the Auth middleware in your server:
1. Use a production wallet implementation (avoid the example wallet in real systems).
2. Insert the Auth middleware in your handler chain before your application handlers.
3. For browser clients, add a CORS handler before the Auth middleware.
4. Ensure clients send properly signed requests following BRC-103/104.
5. Gracefully handle shutdown signals and errors.
