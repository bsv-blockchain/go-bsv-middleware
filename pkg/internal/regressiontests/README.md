# Regression Tests

This package contains regression tests designed to check the compatibility of the middleware with clients written in TypeScript.
These tests ensure that the middleware correctly implements the BSV specifications and can interact with TypeScript clients.

## Purpose

The regression tests verify that:
- The middleware's authentication mechanisms work correctly with TypeScript clients
- HTTP requests and responses are properly handled

## Prerequisites

To run the regression tests, you need:
- Go programming language
- Node.js with npm

## Running Regression Tests

Run the regression tests using the following command from the project root:
```bash
go test -v -tags regressiontest ./pkg/internal/regressiontests/...
```

## TypeScript Package

The tests call npm to run code written in TypeScript located in the `internal/typescript` package. This package contains:
- TypeScript scripts for making authenticated requests to the middleware
- Go lang wrapper/abstraction which is able to call the TypeScript scripts

The TypeScript code uses the `@bsv/sdk` package to implement the client-side of the BSV specifications.

## Warning

These tests require npm and will install dependencies and run TypeScript code during test execution.
Make sure you have Node.js and npm installed before running these tests.
