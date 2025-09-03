package authentication

import "context"

// GetIdentityFromContext retrieves identity from the request context
func GetIdentityFromContext(ctx context.Context) (string, bool) {
	value := ctx.Value(IdentityKey)
	if value == nil {
		return "", false
	}

	identityKey, ok := value.(string)
	return identityKey, ok
}
