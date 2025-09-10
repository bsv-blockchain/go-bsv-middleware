# BSV Authentication Examples

This directory contains examples demonstrating how to use the BSV authentication middleware for implementing BRC-103/104 mutual authentication in Go applications.

## Overview

The examples showcase different authentication scenarios using the `go-bsv-middleware` library:

1. [Auth-Enabled HTTP Server (Standalone)](./auth_basic_server/auth_basic_server.md)
2. [Basic Authenticated Request (Server + Client in one process)](./auth_basic/auth_basic.md)

## Requirements

- Go 1.24 or higher
- The `go-bsv-middleware` package and its dependencies

## Run examples

From the repository root:

```bash
# Standalone server
go run ./examples/auth/auth_basic_server/auth_basic_server_main.go

# Server + client in one process
go run ./examples/auth/auth_basic/auth_basic_main.go
```

## Key Concepts

- **BRC-103/104**: Bitcoin SV Peer-to-Peer Mutual Authentication protocol
- **Wallet Interface**: Used for cryptographic operations (signing, verification)
- **Session Management**: Tracks authenticated sessions between requests
- **Certificate Exchange**: Optional verification of client attributes

## Additional Resources

- The middleware implements [BRC-103](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0103.md) and [BRC-104](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0104.md) specifications
