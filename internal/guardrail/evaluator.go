package guardrail

import "context"

// Evaluator produces per-category findings for content. Implementations
// detect; they never decide. Failures must be returned as errors
// (preferably *EvaluationError) and never encoded as findings.
//
// JevEvaluator (internal/jev) is the initial implementation; regex, DLP,
// URL reputation or custom classifiers can implement the same interface.
type Evaluator interface {
	Evaluate(ctx context.Context, input EvaluationInput, policy Policy) (Evaluation, error)
}

// ReadinessChecker is optionally implemented by evaluators whose
// dependencies can be health-checked without running an evaluation.
type ReadinessChecker interface {
	Ready(ctx context.Context) error
}
