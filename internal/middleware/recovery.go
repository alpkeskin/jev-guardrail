package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
)

// writeTracker records whether a response has been started.
type writeTracker struct {
	http.ResponseWriter
	wrote bool
}

func (t *writeTracker) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *writeTracker) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *writeTracker) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// Recover converts panics into a response produced by onPanic and logs
// the stack trace with the request's logger. If the response was already
// started, the connection is aborted instead, so the client never receives
// a corrupted body that mixes two responses.
func Recover(onPanic http.HandlerFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tw := &writeTracker{ResponseWriter: w}
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rec)
				}
				reqctx.LoggerFromContext(r.Context()).Error("panic recovered",
					slog.Any("panic", rec), slog.String("stack", string(debug.Stack())),
					slog.Bool("response_started", tw.wrote))
				if tw.wrote {
					panic(http.ErrAbortHandler)
				}
				onPanic(w, r)
			}()
			next.ServeHTTP(tw, r)
		})
	}
}
