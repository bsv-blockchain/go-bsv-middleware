package httperror

// Error is a struct passed to error handler to serialize it in response.
type Error struct {
	StatusCode int
	// Code is a short machine-readable identifier for the failure (e.g.
	// "UNAUTHORIZED", "ERR_AUTH_FAILED"), matching the BRC-103/BRC-104 wire
	// error shape {"status":"error","code":"...")}. Empty when no specific
	// code applies (defaults to "ERR_INTERNAL_SERVER_ERROR" in that case).
	Code    string
	Message string
	Err     error
}
