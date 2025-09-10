//go:build gengrpc

// Package typescript provides the Go gRPC client generated from proto/auth_fetch.proto.
//
// Code generation:
//
//	Ensure you have the following installed:
//	  - protoc (https://protobuf.dev/installation/)
//	  - protoc-gen-go:     go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
//	  - protoc-gen-go-grpc: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
//
//	Then run:
//	  go generate ./...
//
//go:generate go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
//go:generate go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
//go:generate sh -c "cd proto && protoc --go_out=.. --go_opt=paths=source_relative --go-grpc_out=.. --go-grpc_opt=paths=source_relative auth_fetch.proto"
package typescript
