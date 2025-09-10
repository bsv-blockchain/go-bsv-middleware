package testabilities

import "log/slog"

type Options struct {
	logger      *slog.Logger
	serverPorts []int
}

// WithServerPorts sets the list of port numbers to select from when starting the test server.
// This is especially useful when we want to run tests with a known port range beforehand.
// (especially in regression tests)
func WithServerPorts(ports []int) func(*Options) {
	return func(options *Options) {
		options.serverPorts = ports
	}
}
