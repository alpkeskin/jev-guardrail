// Package jev adapts the Jev detection service to the guardrail.Evaluator
// interface. Jev wire types never leave this package: results are mapped
// into the service's own taxonomy by mapper.go.
package jev

// EvaluateRequest is the Jev evaluation request body.
type EvaluateRequest struct {
	Input     string            `json:"input"`
	InputType string            `json:"input_type,omitempty"`
	Detectors []string          `json:"detectors"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// EvaluateResponse is the Jev evaluation response body.
type EvaluateResponse struct {
	Results []DetectorResult `json:"results"`
}

// DetectorResult is one Jev detector's output.
type DetectorResult struct {
	Detector string   `json:"detector"`
	Score    *float64 `json:"score"`
	// Label and Explanation are Jev-internal and intentionally never
	// propagated to the public API or logs.
	Label       string `json:"label,omitempty"`
	Explanation string `json:"explanation,omitempty"`
}
