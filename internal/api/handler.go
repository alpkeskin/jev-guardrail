// Package api implements the HTTP API of the guardrail service.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

// Guarder runs the guardrail pipeline.
type Guarder interface {
	Guard(ctx context.Context, policy guardrail.Policy, input guardrail.EvaluationInput) guardrail.Judgment
}

// ReadinessCheck is a named dependency check used by GET /ready.
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// Handler serves the API endpoints.
type Handler struct {
	guard        Guarder
	maxBodyBytes int64
	checks       []ReadinessCheck
	readyTimeout time.Duration
	draining     atomic.Bool
}

// NewHandler returns a Handler.
func NewHandler(g Guarder, maxBodyBytes int64, checks []ReadinessCheck) *Handler {
	return &Handler{guard: g, maxBodyBytes: maxBodyBytes, checks: checks, readyTimeout: 2 * time.Second}
}

// Guard serves POST /v1/guard.
func (h *Handler) Guard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := reqctx.LoggerFromContext(ctx)

	input, rerr := decodeGuardRequest(w, r, h.maxBodyBytes)
	if rerr != nil {
		logger.LogAttrs(ctx, slog.LevelInfo, "invalid guard request",
			slog.String("reason_code", string(rerr.code)), slog.String("error", rerr.Error()))
		writeJudgment(w, r, rerr.status, guardrail.FailedJudgment(rerr.code))
		return
	}

	pol, ok := reqctx.PolicyFromContext(ctx)
	if !ok {
		logger.Error("no policy attached to request context")
		writeJudgment(w, r, http.StatusInternalServerError, guardrail.FailedJudgment(guardrail.ReasonInvalidPolicy))
		return
	}

	ctx = reqctx.WithLogger(ctx, logger.With(slog.String("content_type", string(input.ContentType))))
	j := h.guard.Guard(ctx, pol, input)
	writeJudgment(w, r, statusFor(j), j)
}

// Health serves GET /health: the process is alive.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// SetDraining makes /ready fail so load balancers stop routing new
// traffic before the server shuts down. In-flight and new requests are
// still served until the listener closes.
func (h *Handler) SetDraining() { h.draining.Store(true) }

// Draining reports whether SetDraining was called.
func (h *Handler) Draining() bool { return h.draining.Load() }

// Ready serves GET /ready: configuration is loaded, dependencies are
// reachable and the instance is not shutting down. It never runs a
// guardrail evaluation.
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	if h.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining", "checks": map[string]string{}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.readyTimeout)
	defer cancel()

	status, results := http.StatusOK, map[string]string{}
	for _, c := range h.checks {
		if err := c.Check(ctx); err != nil {
			reqctx.LoggerFromContext(ctx).Warn("readiness check failed",
				slog.String("check", c.Name), slog.String("error", err.Error()))
			results[c.Name] = "unavailable"
			status = http.StatusServiceUnavailable
			continue
		}
		results[c.Name] = "ok"
	}
	state := "ready"
	if status != http.StatusOK {
		state = "not_ready"
	}
	writeJSON(w, status, map[string]any{"status": state, "checks": results})
}
