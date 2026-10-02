package guardrail

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestServiceGuard(t *testing.T) {
	in := EvaluationInput{Content: "hello", ContentType: ContentPrompt}
	tests := []struct {
		name       string
		mock       *MockEvaluator
		want       Decision
		wantReason ReasonCode
	}{
		{"passed", &MockEvaluator{Evaluation: Evaluation{Findings: []Finding{{Category: CategoryPromptInjection, Score: 0.1}}}}, Passed, ""},
		{"blocked", &MockEvaluator{Evaluation: Evaluation{Findings: []Finding{{Category: CategoryPromptInjection, Score: 0.94}}}}, Blocked, ReasonCode(CategoryPromptInjection)},
		{"jev timeout", &MockEvaluator{Err: NewEvaluationError(ReasonJevTimeout, context.DeadlineExceeded)}, Failed, ReasonJevTimeout},
		{"jev unavailable", &MockEvaluator{Err: NewEvaluationError(ReasonJevUnavailable, errors.New("dial"))}, Failed, ReasonJevUnavailable},
		{"wrapped evaluation error", &MockEvaluator{Err: fmt.Errorf("outer: %w", NewEvaluationError(ReasonJevError, nil))}, Failed, ReasonJevError},
		{"unclassified error", &MockEvaluator{Err: errors.New("boom")}, Failed, ReasonInternalError},
		{"error with findings is still failed", &MockEvaluator{
			Evaluation: Evaluation{Findings: []Finding{{Category: CategoryPromptInjection, Score: 0.99}}},
			Err:        NewEvaluationError(ReasonJevError, nil),
		}, Failed, ReasonJevError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j := NewService(tc.mock, nil).Guard(context.Background(), testPolicy(), in)
			if j.Decision != tc.want {
				t.Fatalf("decision = %s, want %s", j.Decision, tc.want)
			}
			if tc.wantReason != "" && (j.Reason == nil || j.Reason.Code != tc.wantReason) {
				t.Fatalf("reason = %+v, want %s", j.Reason, tc.wantReason)
			}
			if j.Decision == Failed && (len(j.Findings) != 0 || j.Reason.Message == "" || !j.Reason.Code.IsFailure()) {
				t.Fatalf("bad failed judgment: %+v", j)
			}
			calls := tc.mock.Calls()
			if len(calls) != 1 || calls[0].Input != in || calls[0].Policy.ClientID != "test" {
				t.Fatalf("unexpected calls: %+v", calls)
			}
		})
	}
}

func TestFailedJudgmentRejectsSecurityCodes(t *testing.T) {
	j := FailedJudgment(ReasonCode(CategoryPromptInjection))
	if j.Reason.Code != ReasonInternalError {
		t.Fatalf("FAILED must never carry a security reason, got %s", j.Reason.Code)
	}
}
