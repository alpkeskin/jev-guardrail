package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

type openAPIDoc struct {
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Enum []string `yaml:"enum"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func sorted(s []string) []string { out := slices.Clone(s); sort.Strings(out); return out }

// TestOpenAPIMatchesTaxonomy prevents the published contract from drifting
// from the code.
func TestOpenAPIMatchesTaxonomy(t *testing.T) {
	var doc openAPIDoc
	if err := yaml.Unmarshal(OpenAPISpec, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}

	var cats, failures, types []string
	for _, c := range guardrail.Categories() {
		cats = append(cats, string(c.Category))
	}
	for _, c := range guardrail.FailureCodes() {
		failures = append(failures, string(c))
	}
	for _, c := range guardrail.ContentTypes() {
		types = append(types, string(c))
	}
	for name, want := range map[string][]string{"Category": cats, "FailureCode": failures, "ContentType": types} {
		got := doc.Components.Schemas[name].Enum
		if !slices.Equal(sorted(got), sorted(want)) {
			t.Errorf("schema %s enum = %v, code has %v", name, got, want)
		}
	}
	for _, p := range []string{"/v1/guard", "/health", "/ready", "/openapi.yaml"} {
		if _, ok := doc.Paths[p]; !ok {
			t.Errorf("path %s not documented", p)
		}
	}
}

type passGuard struct{}

func (passGuard) Guard(context.Context, guardrail.Policy, guardrail.EvaluationInput) guardrail.Judgment {
	return guardrail.Judgment{Decision: guardrail.Passed}
}

func TestReadyDraining(t *testing.T) {
	h := NewHandler(passGuard{}, 1024, []ReadinessCheck{{Name: "x", Check: func(context.Context) error { return nil }}})

	w := httptest.NewRecorder()
	h.Ready(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != 200 {
		t.Fatalf("ready = %d", w.Code)
	}

	h.SetDraining()
	w = httptest.NewRecorder()
	h.Ready(w, httptest.NewRequest("GET", "/ready", nil))
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusServiceUnavailable || body["status"] != "draining" {
		t.Fatalf("draining ready = %d %s", w.Code, w.Body)
	}
	// Liveness is unaffected by draining.
	w = httptest.NewRecorder()
	h.Health(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 200 {
		t.Fatalf("health while draining = %d", w.Code)
	}
}

func TestStatusForFailedWithoutReason(t *testing.T) {
	// Defensive: must not panic.
	if got := statusFor(guardrail.Judgment{Decision: guardrail.Failed}); got != http.StatusInternalServerError {
		t.Fatalf("status = %d", got)
	}
}
