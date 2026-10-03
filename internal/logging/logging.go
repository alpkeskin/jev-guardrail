// Package logging builds the service's structured slog logger and carries
// the request-scoped logger through context.Context.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// New returns a slog logger writing to w. format is "json" or "text".
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch strings.ToLower(format) {
	case "", "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q", format)
	}
}

type loggerKey struct{}

// WithLogger returns a context carrying logger.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// FromContext returns the request-scoped logger, or slog.Default().
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
