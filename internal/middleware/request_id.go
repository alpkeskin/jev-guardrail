// Package middleware contains the HTTP middleware chain: request ID,
// client ID, access logging, panic recovery, authentication and policy
// resolution.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
)

// HeaderRequestID carries the request ID in requests and responses.
const HeaderRequestID = "X-Request-ID"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// NewRequestID returns a random request ID.
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "req_" + hex.EncodeToString(b[:])
}

// RequestID ensures every request has an ID. A valid incoming X-Request-ID
// is reused; a missing or malformed one is replaced by a generated ID. The
// ID is stored in the context, bound to the request logger and echoed in
// the response header.
func RequestID(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(HeaderRequestID)
			replaced := id != "" && !requestIDPattern.MatchString(id)
			if id == "" || replaced {
				id = NewRequestID()
			}
			logger := base.With(slog.String("request_id", id))
			if replaced {
				logger.Warn("malformed X-Request-ID replaced with generated ID")
			}
			ctx := reqctx.WithRequestID(r.Context(), id)
			ctx = reqctx.WithLogger(ctx, logger)
			w.Header().Set(HeaderRequestID, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
