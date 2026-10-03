package jev

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

// API is the subset of the Jev client used by the evaluator.
type API interface {
	Evaluate(ctx context.Context, req SystemOneRequest) (SystemOneResponse, error)
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

// Evaluate asks Jev one question per enabled category of the policy, all
// in a single request (Jev answers them in parallel), and maps the answers
// into taxonomy findings.
func (e *Evaluator) Evaluate(ctx context.Context, input guardrail.EvaluationInput, policy guardrail.Policy) (guardrail.Evaluation, error) {
	cats := policy.EnabledCategories()
	questions := make(map[string]Question, len(cats))
	for _, c := range cats {
		if id, q, ok := QuestionFor(c); ok {
			questions[id] = q
		}
	}
	if len(questions) == 0 {
		// Nothing to evaluate: a successful, empty evaluation.
		return guardrail.Evaluation{Findings: []guardrail.Finding{}}, nil
	}

	req := SystemOneRequest{
		State:     State{Source: SourceFor(input.ContentType), Content: input.Content},
		Questions: questions,
	}
	resp, err := e.api.Evaluate(ctx, req)
	if err != nil {
		return guardrail.Evaluation{}, err
	}

	findings, ignored, err := MapAnswers(resp.Answers)
	if err != nil {
		return guardrail.Evaluation{}, guardrail.NewEvaluationError(guardrail.ReasonJevError, fmt.Errorf("map jev answers: %w", err))
	}
	// Every question must be answered. Otherwise a category was never
	// evaluated and a PASSED judgment would be unreliable.
	got := make(map[guardrail.Category]bool, len(findings))
	for _, f := range findings {
		got[f.Category] = true
	}
	for _, c := range cats {
		if _, _, asked := QuestionFor(c); asked && !got[c] {
			return guardrail.Evaluation{}, guardrail.NewEvaluationError(guardrail.ReasonJevError,
				fmt.Errorf("jev returned no answer for requested category %s", c))
		}
	}
	// Map iteration order is random; keep findings in taxonomy order.
	sort.Slice(findings, func(i, j int) bool { return categoryRank[findings[i].Category] < categoryRank[findings[j].Category] })

	log := reqctx.LoggerFromContext(ctx)
	if len(ignored) > 0 {
		log.LogAttrs(ctx, slog.LevelDebug, "ignored unexpected jev answers", slog.Any("questions", ignored))
	}
	log.LogAttrs(ctx, slog.LevelDebug, "jev evaluation completed", slog.String("jev_model", resp.Model))
	return guardrail.Evaluation{Findings: findings}, nil
}

var categoryRank = func() map[guardrail.Category]int {
	m := map[guardrail.Category]int{}
	for i, c := range guardrail.Categories() {
		m[c.Category] = i
	}
	return m
}()

// Ready implements guardrail.ReadinessChecker.
func (e *Evaluator) Ready(ctx context.Context) error { return e.api.Ping(ctx) }
