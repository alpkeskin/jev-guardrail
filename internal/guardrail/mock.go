package guardrail

import (
	"context"
	"sync"
)

// MockEvaluator is a deterministic Evaluator for tests. It returns
// Evaluation, or Err when set, and records every call.
type MockEvaluator struct {
	Evaluation Evaluation
	Err        error

	mu    sync.Mutex
	calls []MockCall
}

// MockCall records one Evaluate invocation.
type MockCall struct {
	Ctx    context.Context
	Input  EvaluationInput
	Policy Policy
}

// Evaluate implements Evaluator.
func (m *MockEvaluator) Evaluate(ctx context.Context, input EvaluationInput, policy Policy) (Evaluation, error) {
	m.mu.Lock()
	m.calls = append(m.calls, MockCall{Ctx: ctx, Input: input, Policy: policy})
	m.mu.Unlock()
	if m.Err != nil {
		return Evaluation{}, m.Err
	}
	return m.Evaluation, nil
}

// Calls returns the recorded calls.
func (m *MockEvaluator) Calls() []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MockCall, len(m.calls))
	copy(out, m.calls)
	return out
}
