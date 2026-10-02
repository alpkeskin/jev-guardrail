package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
)

// Recover converts panics into a response produced by onPanic and logs
// the stack trace with the request's logger.
func Recover(onPanic http.HandlerFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				reqctx.LoggerFromContext(r.Context()).Error("panic recovered",
					slog.Any("panic", rec), slog.String("stack", string(debug.Stack())))
				onPanic(w, r)
			}()
			next.ServeHTTP(w, r)
		})
	}
}
