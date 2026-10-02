// Package reqctx carries request-scoped values (request ID, client ID,
// resolved policy, caller and logger) through context.Context using typed
// keys.
package reqctx

import (
	"context"
	"log/slog"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/logging"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	clientIDKey
	policyKey
	callerKey
)

// WithRequestID attaches the request ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request ID, or "".
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// WithClientID attaches the caller-supplied client ID (policy selector).
func WithClientID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, clientIDKey, id)
}

// ClientID returns the caller-supplied client ID, or "".
// It is a policy selector, not an authenticated identity.
func ClientID(ctx context.Context) string {
	v, _ := ctx.Value(clientIDKey).(string)
	return v
}

// WithPolicy attaches the resolved policy.
func WithPolicy(ctx context.Context, p guardrail.Policy) context.Context {
	return context.WithValue(ctx, policyKey, p)
}

// PolicyFromContext returns the resolved policy and whether one is present.
func PolicyFromContext(ctx context.Context) (guardrail.Policy, bool) {
	p, ok := ctx.Value(policyKey).(guardrail.Policy)
	return p, ok
}

// WithCaller attaches the authenticated caller identity.
func WithCaller(ctx context.Context, caller string) context.Context {
	return context.WithValue(ctx, callerKey, caller)
}

// Caller returns the authenticated caller identity, or "".
func Caller(ctx context.Context) string {
	v, _ := ctx.Value(callerKey).(string)
	return v
}

// WithLogger attaches the request-scoped logger.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return logging.WithLogger(ctx, l)
}

// LoggerFromContext returns the request-scoped logger, or slog.Default().
func LoggerFromContext(ctx context.Context) *slog.Logger {
	return logging.FromContext(ctx)
}
