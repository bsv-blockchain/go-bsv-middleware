package testabilities

import "log/slog"

type Options struct {
	logger *slog.Logger
}

func WithLogger(logger *slog.Logger) func(*Options) {
	return func(options *Options) {
		options.logger = logger
	}
}

func WithoutLogging() func(*Options) {
	return func(options *Options) {
		options.logger = slog.New(slog.DiscardHandler)
	}
}
