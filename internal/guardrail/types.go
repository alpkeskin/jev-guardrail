package guardrail

import (
	"errors"
	"fmt"
)

// Decision is the final judgment of an evaluation.
type Decision string

const (
	// Passed: evaluation completed and no policy rule was violated.
	Passed Decision = "PASSED"
	// Blocked: evaluation completed and at least one blocking rule was violated.
	Blocked Decision = "BLOCKED"
	// Failed: evaluation could not be completed reliably. A failure is not
	// evidence that the content is malicious.
	Failed Decision = "FAILED"
)

// Action is what a matched policy rule does to the judgment.
type Action string

const (
	// ActionBlock turns a match into a BLOCKED judgment.
	ActionBlock Action = "block"
	// ActionReview reports a match as a finding without blocking.
	ActionReview Action = "review"
)

// Valid reports whether a is a supported action.
func (a Action) Valid() bool { return a == ActionBlock || a == ActionReview }

// Rule configures a single taxonomy category within a policy.
type Rule struct {
	Enabled   bool
	Threshold float64
	Action    Action
}

// Policy is a validated, immutable security policy.
type Policy struct {
	Version  string
	ClientID string
	Rules    map[Category]Rule
	// Source is the file the policy was loaded from (diagnostics only).
	Source string
}

// EnabledCategories returns the enabled categories in taxonomy order.
func (p Policy) EnabledCategories() []Category {
	var out []Category
	for _, c := range categories {
		if r, ok := p.Rules[c.Category]; ok && r.Enabled {
			out = append(out, c.Category)
		}
	}
	return out
}

// ContentType describes what kind of content is inspected.
type ContentType string

const (
	ContentPrompt     ContentType = "prompt"
	ContentResponse   ContentType = "response"
	ContentToolInput  ContentType = "tool_input"
	ContentToolOutput ContentType = "tool_output"
	ContentDocument   ContentType = "document"
	ContentText       ContentType = "text"
)

// DefaultContentType is used when the caller does not specify one.
const DefaultContentType = ContentText

// ContentTypes returns all supported content types.
func ContentTypes() []ContentType {
	return []ContentType{ContentPrompt, ContentResponse, ContentToolInput, ContentToolOutput, ContentDocument, ContentText}
}

// Valid reports whether t is a supported content type.
func (t ContentType) Valid() bool {
	switch t {
	case ContentPrompt, ContentResponse, ContentToolInput, ContentToolOutput, ContentDocument, ContentText:
		return true
	}
	return false
}

// EvaluationInput is the evaluator-agnostic description of content to inspect.
type EvaluationInput struct {
	Content     string
	ContentType ContentType
}

// Finding is the result of evaluating one taxonomy category.
type Finding struct {
	Category Category `json:"category"`
	Score    float64  `json:"score"`
	Matched  bool     `json:"matched"`
	Reason   string   `json:"reason,omitempty"`
}

// Evaluation is the raw output of an Evaluator: per-category scores,
// before any policy decision is applied.
type Evaluation struct {
	Findings []Finding
}

// Reason explains a judgment. Clients must decide based on Code.
type Reason struct {
	Code    ReasonCode `json:"code"`
	Message string     `json:"message"`
}

// Judgment is the outcome of the guardrail pipeline.
type Judgment struct {
	Decision Decision
	Reason   *Reason
	Findings []Finding
}

// FailedJudgment builds a FAILED judgment for a failure reason code.
func FailedJudgment(code ReasonCode) Judgment {
	if !code.IsFailure() {
		code = ReasonInternalError
	}
	return Judgment{Decision: Failed, Reason: &Reason{Code: code, Message: failureMessages[code]}}
}

// EvaluationError is an evaluation failure classified into the failure
// taxonomy. Err holds the internal cause and is only ever logged.
type EvaluationError struct {
	Code ReasonCode
	Err  error
}

// NewEvaluationError wraps err with a failure reason code.
func NewEvaluationError(code ReasonCode, err error) *EvaluationError {
	return &EvaluationError{Code: code, Err: err}
}

func (e *EvaluationError) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *EvaluationError) Unwrap() error { return e.Err }

// FailureCode classifies any error into the failure taxonomy.
// Unclassified errors become INTERNAL_ERROR.
func FailureCode(err error) ReasonCode {
	var ee *EvaluationError
	if errors.As(err, &ee) && ee.Code.IsFailure() {
		return ee.Code
	}
	return ReasonInternalError
}
