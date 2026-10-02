package api

import (
	_ "embed"
	"log/slog"
	"net/http"

	"github.com/alpkeskin/jev-guardrail/internal/auth"
	"github.com/alpkeskin/jev-guardrail/internal/middleware"
	"github.com/alpkeskin/jev-guardrail/internal/policy"
)

// OpenAPISpec is the OpenAPI 3.1 description of this API.
//
//go:embed openapi.yaml
var OpenAPISpec []byte

// RouterConfig wires the HTTP router.
type RouterConfig struct {
	Logger        *slog.Logger
	Handler       *Handler
	Authenticator auth.Authenticator
	Resolver      policy.Resolver
	// Observer receives HTTP metrics (optional).
	Observer middleware.HTTPObserver
}

// NewRouter returns the service's HTTP handler.
//
// Every request gets a request ID, client ID, access log/metrics and panic
// recovery. /v1/guard additionally requires authentication and resolves
// the policy; health and documentation endpoints are unauthenticated.
func NewRouter(cfg RouterConfig) http.Handler {
	guard := middleware.Chain(http.HandlerFunc(cfg.Handler.Guard),
		middleware.Recover(WriteInternalFailure),
		middleware.Auth(cfg.Authenticator, WriteUnauthorized),
		middleware.ResolvePolicy(cfg.Resolver),
	)

	mux := http.NewServeMux()
	mux.Handle("POST /v1/guard", guard)
	mux.HandleFunc("GET /health", cfg.Handler.Health)
	mux.HandleFunc("GET /ready", cfg.Handler.Ready)
	mux.HandleFunc("GET /openapi.yaml", serveOpenAPI)

	route := func(r *http.Request) string {
		_, pattern := mux.Handler(r)
		return pattern
	}
	return middleware.Chain(mux,
		middleware.RequestID(cfg.Logger),
		middleware.ClientID,
		middleware.AccessLog(cfg.Observer, route),
		middleware.Recover(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}),
	)
}

func serveOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(OpenAPISpec)
}
