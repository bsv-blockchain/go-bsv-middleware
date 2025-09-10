# gRPC Fetch Server (TypeScript) + Go client

## gRPC code generation

### ⚠️ Requirements
- [protoc](https://protobuf.dev/installation/)

### TypeScript code generation (ts-proto)
This project uses [ts-proto](https://github.com/stephenh/ts-proto) to generate TypeScript types and gRPC service definitions from the `.proto` files.

- Generated code lives under `src/gen` and is git-ignored by default.
- The build step automatically generates the code.
- You can generate code manually with:
```
npm run proto:gen
```

### Go gRPC client generation
A Go client for the `typescript.AuthFetch` service is generated from `proto/auth_fetch.proto`.

Then run from repo root or this directory:
```sh
go generate -tags=gengrpc ./...
```
This will generate `auth_fetch.pb.go` and `auth_fetch_grpc.pb.go` in the current directory with package `typescript`.

## Running the server

### From Code

```shell
npm install
```

Build and run the gRPC server (default port 50050):
```shell
npm run dev
```

You should see a log similar to:

```text
gRPC server is running on 0.0.0.0:50050
Service: typescript.AuthFetch | Method: Fetch(url, config, options) -> FetchResponse
```

## Configuration
- Environment variables:
  - `HOST` (default `0.0.0.0`)
  - `PORT` (default `50050`)

### From Docker

First build the image:
(make sure to be in the `typescript` directory)

```shell
docker build -t auth-fetch-grpc .
```

then run the container:
```shell
docker run --rm -p 50050:50050 --name auth-fetch-grpc auth-fetch-grpc
```
