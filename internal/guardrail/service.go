package guardrail

import (
	"context"
	"log/slog"

	"github.com/alpkeskin/jev-guardrail/internal/logging"
)

// Service runs the guardrail pipeline: evaluate, then decide.
type Service struct {
	evaluator Evaluator
	engine    PolicyEngine
}

// NewService returns a Service. A nil engine defaults to ThresholdEngine.
func NewService(evaluator Evaluator, engine PolicyEngine) *Service {
	if engine == nil {
		engine = ThresholdEngine{}
	}
	return &Service{evaluator: evaluator, engine: engine}
}

// Guard evaluates input against policy. It always returns a judgment;
// evaluator errors become FAILED, never BLOCKED.
func (s *Service) Guard(ctx context.Context, policy Policy, input EvaluationInput) Judgment {
	log := logging.FromContext(ctx)

	eval, err := s.evaluator.Evaluate(ctx, input, policy)
	if err != nil {
		j := FailedJudgment(FailureCode(err))
		log.LogAttrs(ctx, slog.LevelWarn, "guardrail evaluation failed",
			slog.String("judgment", string(j.Decision)),
			slog.String("reason_code", string(j.Reason.Code)),
			slog.String("error", err.Error()),
		)
		return j
	}

	j := s.engine.Decide(ctx, policy, eval.Findings)
	attrs := []slog.Attr{
		slog.String("judgment", string(j.Decision)),
		slog.Int("matched_findings", len(j.Findings)),
	}
	if j.Reason != nil {
		attrs = append(attrs, slog.String("reason_code", string(j.Reason.Code)))
	}
	log.LogAttrs(ctx, slog.LevelInfo, "guardrail evaluation completed", attrs...)
	return j
}

// Ready reports whether the evaluator's dependencies are ready.
func (s *Service) Ready(ctx context.Context) error {
	if rc, ok := s.evaluator.(ReadinessChecker); ok {
		return rc.Ready(ctx)
	}
	return nil
}
