package jev

import (
	"context"
	"fmt"
	"log/slog"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

// API is the subset of the Jev client used by the evaluator.
type API interface {
	Evaluate(ctx context.Context, req EvaluateRequest) (EvaluateResponse, error)
	Ping(ctx context.Context) error
}

// Evaluator implements guardrail.Evaluator using Jev (the "JevEvaluator").
type Evaluator struct {
	api API
}

var (
	_ guardrail.Evaluator        = (*Evaluator)(nil)
	_ guardrail.ReadinessChecker = (*Evaluator)(nil)
)

// NewEvaluator returns a Jev-backed evaluator.
func NewEvaluator(api API) *Evaluator { return &Evaluator{api: api} }

// Evaluate asks Jev to run the detectors for the policy's enabled
// categories and maps the results into taxonomy findings.
func (e *Evaluator) Evaluate(ctx context.Context, input guardrail.EvaluationInput, policy guardrail.Policy) (guardrail.Evaluation, error) {
	cats := policy.EnabledCategories()
	detectors := make([]string, 0, len(cats))
	for _, c := range cats {
		if d, ok := DetectorFor(c); ok {
			detectors = append(detectors, d)
		}
	}
	if len(detectors) == 0 {
		// Nothing to evaluate: a successful, empty evaluation.
		return guardrail.Evaluation{Findings: []guardrail.Finding{}}, nil
	}

	req := EvaluateRequest{
		Input:     input.Content,
		InputType: string(input.ContentType),
		Detectors: detectors,
		Metadata:  map[string]string{},
	}
	if id := reqctx.RequestID(ctx); id != "" {
		req.Metadata["request_id"] = id
	}
	if policy.ClientID != "" {
		req.Metadata["policy_id"] = policy.ClientID
	}

	resp, err := e.api.Evaluate(ctx, req)
	if err != nil {
		return guardrail.Evaluation{}, err
	}

	findings, ignored, err := MapResults(resp.Results)
	if err != nil {
		return guardrail.Evaluation{}, guardrail.NewEvaluationError(guardrail.ReasonJevError, fmt.Errorf("map jev results: %w", err))
	}
	// Every requested detector must report. Otherwise a category was never
	// evaluated and a PASSED judgment would be unreliable.
	got := make(map[guardrail.Category]bool, len(findings))
	for _, f := range findings {
		got[f.Category] = true
	}
	for _, c := range cats {
		if _, mapped := DetectorFor(c); mapped && !got[c] {
			return guardrail.Evaluation{}, guardrail.NewEvaluationError(guardrail.ReasonJevError,
				fmt.Errorf("jev returned no result for requested category %s", c))
		}
	}
	if len(ignored) > 0 {
		reqctx.LoggerFromContext(ctx).LogAttrs(ctx, slog.LevelDebug, "ignored unmapped jev detectors",
			slog.Any("detectors", ignored))
	}
	return guardrail.Evaluation{Findings: findings}, nil
}

// Ready implements guardrail.ReadinessChecker.
func (e *Evaluator) Ready(ctx context.Context) error { return e.api.Ping(ctx) }
