package authctx

import (
	"context"
	"fmt"
	"net/http"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/go-softwarelab/common/pkg/to"
)

var unknownIdentityValue ec.PublicKey
var unknownIdentity *ec.PublicKey

type contextKey string

// IdentityKey stores identity in context.
const IdentityKey contextKey = "identity_key"

// RequestKey stores request in context.
const RequestKey contextKey = "http_request"

// ResponseKey stores response writer in context.
const ResponseKey contextKey = "http_response"

func WithRequest(ctx context.Context, request *http.Request) context.Context {
	return context.WithValue(ctx, RequestKey, request)
}

func WithResponse(ctx context.Context, response http.ResponseWriter) context.Context {
	return context.WithValue(ctx, ResponseKey, response)
}

func WithUnknownIdentity(ctx context.Context) context.Context {
	return WithIdentity(ctx, unknownIdentity)
}

func WithIdentity(ctx context.Context, identity *ec.PublicKey) context.Context {
	identityValue := to.ValueOr(identity, unknownIdentityValue)

	return context.WithValue(ctx, IdentityKey, identityValue)
}

func ShouldGetResponse(ctx context.Context) (http.ResponseWriter, error) {
	contextValue := ctx.Value(ResponseKey)
	if contextValue == nil {
		return nil, fmt.Errorf("%s not found in context", ResponseKey)
	}

	resp, ok := contextValue.(http.ResponseWriter)
	if !ok {
		return nil, fmt.Errorf("%s contains unexpected type %T", ResponseKey, contextValue)
	}

	return resp, nil
}

func ShouldGetRequest(ctx context.Context) (*http.Request, error) {
	contextValue := ctx.Value(RequestKey)
	if contextValue == nil {
		return nil, fmt.Errorf("%s not found in context", RequestKey)
	}

	req, ok := contextValue.(*http.Request)
	if !ok {
		return nil, fmt.Errorf("%s contains unexpected type %T", RequestKey, contextValue)
	}

	return req, nil
}

func ShouldGetIdentity(ctx context.Context) (*ec.PublicKey, error) {
	contextValue := ctx.Value(IdentityKey)
	if contextValue == nil {
		return nil, fmt.Errorf("%s not found in context", IdentityKey)
	}

	identity, ok := contextValue.(ec.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s contains unexpected type %T", IdentityKey, contextValue)
	}

	if identity == unknownIdentityValue {
		return unknownIdentity, nil
	}

	return &identity, nil
}

func IsUnauthenticated(ctx context.Context) bool {
	contextValue := ctx.Value(IdentityKey)
	if contextValue == nil {
		return true
	}

	identity, ok := contextValue.(ec.PublicKey)
	if !ok {
		return true
	}

	return IsUnknownIdentity(&identity)
}

func IsUnknownIdentity(identity *ec.PublicKey) bool {
	identityValue := to.ValueOr(identity, unknownIdentityValue)
	return identityValue == unknownIdentityValue
}
