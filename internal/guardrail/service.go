package guardrail

import (
	"context"
	"log/slog"

	"github.com/alpkeskin/jev-guardrail/internal/logging"
)

// JudgmentObserver is notified of every judgment (e.g. for metrics).
type JudgmentObserver interface {
	ObserveJudgment(ctx context.Context, policy Policy, j Judgment)
}

// Service runs the guardrail pipeline: evaluate, then decide.
type Service struct {
	evaluator Evaluator
	engine    PolicyEngine
	observer  JudgmentObserver
}

// Option configures a Service.
type Option func(*Service)

// WithObserver registers a JudgmentObserver.
func WithObserver(o JudgmentObserver) Option { return func(s *Service) { s.observer = o } }

// NewService returns a Service. A nil engine defaults to ThresholdEngine.
func NewService(evaluator Evaluator, engine PolicyEngine, opts ...Option) *Service {
	if engine == nil {
		engine = ThresholdEngine{}
	}
	s := &Service{evaluator: evaluator, engine: engine}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Guard evaluates input against policy. It always returns a judgment;
// evaluator errors become FAILED, never BLOCKED.
func (s *Service) Guard(ctx context.Context, policy Policy, input EvaluationInput) Judgment {
	j := s.guard(ctx, policy, input)
	if s.observer != nil {
		s.observer.ObserveJudgment(ctx, policy, j)
	}
	return j
}

func (s *Service) guard(ctx context.Context, policy Policy, input EvaluationInput) Judgment {
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

	j, ok := validJudgment(s.engine.Decide(ctx, policy, eval.Findings))
	if !ok {
		log.Error("policy engine returned an invalid judgment")
	}
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

// validJudgment enforces the judgment invariants on engine output, so a
// buggy or custom PolicyEngine can never break the API contract:
// PASSED has no reason (or NONE), BLOCKED carries a security reason and
// FAILED carries a failure reason.
func validJudgment(j Judgment) (Judgment, bool) {
	switch j.Decision {
	case Passed:
		if j.Reason == nil || j.Reason.Code == ReasonNone {
			return j, true
		}
	case Blocked:
		if j.Reason != nil && Category(j.Reason.Code).IsKnown() {
			return j, true
		}
	case Failed:
		if j.Reason != nil && j.Reason.Code.IsFailure() {
			return FailedJudgment(j.Reason.Code), true
		}
	}
	return FailedJudgment(ReasonInternalError), false
}
