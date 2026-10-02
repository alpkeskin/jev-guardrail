package middleware

import (
	"log/slog"
	"net/http"
	"time"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// HTTPObserver records per-request HTTP telemetry.
type HTTPObserver interface {
	ObserveHTTP(route, method string, status int, d time.Duration)
}

// RouteFunc returns a bounded route label for a request (e.g. the mux
// pattern), never the raw path.
type RouteFunc func(*http.Request) string

var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
}

// AccessLog logs one line per request and reports it to obs (optional).
// Request bodies are never logged. Label values are bounded so arbitrary
// paths or methods cannot create unbounded metric series.
func AccessLog(obs HTTPObserver, route RouteFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			// Resolve the route before serving; handlers may replace r.
			label := "unmatched"
			if route != nil {
				if l := route(r); l != "" {
					label = l
				}
			}
			defer func() {
				// Runs even when the handler aborts with a panic.
				if rec.status == 0 {
					rec.status = http.StatusOK
				}
				d := time.Since(start)
				method := r.Method
				if !knownMethods[method] {
					method = "OTHER"
				}
				if obs != nil {
					obs.ObserveHTTP(label, method, rec.status, d)
				}
				reqctx.LoggerFromContext(r.Context()).LogAttrs(r.Context(), slog.LevelInfo, "http request",
					slog.String("method", method),
					slog.String("route", label),
					slog.Int("status", rec.status),
					slog.Duration("duration", d),
				)
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// Chain applies middleware so that the first one listed runs first.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
