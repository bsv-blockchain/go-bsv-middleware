package httperror

// Error is a struct passed to error handler to serialize it in response.
type Error struct {
	StatusCode int
	Message    string
	Err        error
}
