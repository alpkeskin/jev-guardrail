package middleware

import (
	"log/slog"
	"net/http"

	"github.com/alpkeskin/jev-guardrail/internal/auth"
	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
)

// Auth rejects unauthenticated requests via onFail and records the
// authenticated caller in the context and logger.
func Auth(a auth.Authenticator, onFail http.HandlerFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			caller, err := a.Authenticate(r)
			if err != nil {
				reqctx.LoggerFromContext(ctx).Warn("authentication failed")
				onFail(w, r)
				return
			}
			ctx = reqctx.WithCaller(ctx, caller)
			ctx = reqctx.WithLogger(ctx, reqctx.LoggerFromContext(ctx).With(slog.String("caller", caller)))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
