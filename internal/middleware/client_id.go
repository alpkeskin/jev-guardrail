package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
	"github.com/alpkeskin/jev-guardrail/internal/policy"
)

// HeaderClientID selects the policy. It is not an authentication mechanism.
const HeaderClientID = "X-Client-ID"

// ClientID stores the caller-supplied X-Client-ID in the context and binds
// it to the request logger. A malformed value is discarded (the request
// then resolves to the default policy).
func ClientID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get(HeaderClientID))
		if id == "" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		logger := reqctx.LoggerFromContext(ctx)
		if !policy.ValidClientID(id) {
			logger.Warn("malformed X-Client-ID ignored")
			next.ServeHTTP(w, r)
			return
		}
		ctx = reqctx.WithClientID(ctx, id)
		ctx = reqctx.WithLogger(ctx, logger.With(slog.String("client_id", id)))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ResolvePolicy attaches the policy selected by the client ID to the
// context. Unknown or missing client IDs resolve to the default policy.
func ResolvePolicy(resolver policy.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			clientID := reqctx.ClientID(ctx)
			p, found := resolver.Resolve(clientID)
			logger := reqctx.LoggerFromContext(ctx).With(slog.String("policy_id", p.ClientID))
			if clientID != "" && clientID != p.ClientID && !found {
				// Surface silent fallbacks (e.g. a typo or wrong case in
				// X-Client-ID) on every request log line.
				logger = logger.With(slog.Bool("policy_fallback", true))
			}
			ctx = reqctx.WithPolicy(ctx, p)
			ctx = reqctx.WithLogger(ctx, logger)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
