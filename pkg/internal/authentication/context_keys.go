package authentication

import (
	"context"
	"fmt"
	"net/http"
)

type contextKey string

// TODO: move this file to a separate package when implementing #127

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
