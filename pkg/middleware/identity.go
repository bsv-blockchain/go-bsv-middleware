package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/authctx"
)

// ShouldGetIdentity returns the identity from the context.
//
// Returns ErrUnknownIdentity when the auth middleware is set to allow unauthenticated
// access and the client does not perform mutual authentication.
// This can then be checked against IsUnknownIdentity to determine if the identity is unknown.
// Alternatively, you can use ShouldGetAuthenticatedIdentity to ensure that the identity is always known.
//
// Returns an error if the context does not contain an identity, which indicates a potentially invalid server setup.
func ShouldGetIdentity(ctx context.Context) (*ec.PublicKey, error) {
	identity, err := authctx.ShouldGetIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get identity from context: %w", err)
	}

	return identity, nil
}

// ErrUnknownIdentity is returned from ShouldGetAuthenticatedIdentity when the identity is unknown.
var ErrUnknownIdentity = errors.New("unknown identity")

// ShouldGetAuthenticatedIdentity returns the identity from the context.
//
// Returns the error ErrUnknownIdentity when the auth middleware is set to allow unauthenticated
// access and the client does not perform mutual authentication.
// Alternatively, you can use ShouldGetIdentity if you want to allow unauthenticated access.
//
// Returns an error if the context does not contain an identity, which indicates a potentially invalid server setup.
func ShouldGetAuthenticatedIdentity(ctx context.Context) (*ec.PublicKey, error) {
	identity, err := ShouldGetIdentity(ctx)
	if err != nil {
		return nil, err
	}

	if IsUnknownIdentity(identity) {
		return nil, ErrUnknownIdentity
	}

	return identity, nil
}

// IsNotAuthenticatedRequest returns true if the request does not contain an authenticated identity.
func IsNotAuthenticatedRequest(req *http.Request) bool {
	return authctx.IsUnauthenticated(req.Context())
}

// IsNotAuthenticated returns true if the context does not contain an authenticated identity.
func IsNotAuthenticated(ctx context.Context) bool {
	return authctx.IsUnauthenticated(ctx)
}

// IsUnknownIdentity returns true if the identity is unknown.
// An unknown identity is used when the auth middleware is set to allow unauthenticated access,
// and the client does not perform mutual authentication.
//
// A nil identity is also considered unknown.
func IsUnknownIdentity(identity *ec.PublicKey) bool {
	return authctx.IsUnknownIdentity(identity)
}
