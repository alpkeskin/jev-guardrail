// Package jev adapts TypeSafe's Jev model (the System One API) to the
// guardrail.Evaluator interface. Jev wire types never leave this package:
// answers are mapped into the service's own taxonomy by questions.go.
package jev

// SystemOneRequest is the body of POST /v1/systemone.
type SystemOneRequest struct {
	State     State               `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]Question `json:"questions"`
}

// State is the content Jev judges. Keeping the screened text in a named
// field lets every question refer to it unambiguously as `content`, and
// Source tells the model where the text came from.
type State struct {
	Source  string `json:"source"`
	Content string `json:"content"`
}

// Question is one typed System One question. Only Nouls are used: each
// category is an independent yes/no judgment whose probability is the
// finding score.
type Question struct {
	Type         string        `json:"type"`
	Instructions string        `json:"instructions"`
	Criteria     *NoulCriteria `json:"criteria,omitempty"`
}

// NoulCriteria describes what a yes and a no mean for a Noul.
type NoulCriteria struct {
	True  string `json:"true"`
	False string `json:"false"`
}

// SystemOneResponse is the System One response body.
type SystemOneResponse struct {
	// Model is the resolved model version (e.g. "jev-1.13.0" for
	// "jev-latest").
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
}

// Answer is one question's answer. Other answer fields (probabilities,
// confidence, legend) are not needed for Nouls and are ignored.
type Answer struct {
	Type string   `json:"type"`
	Noul *float64 `json:"noul"`
}

const questionTypeNoul = "noul"
