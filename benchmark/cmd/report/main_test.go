package main

import (
	"math"
	"testing"

	"github.com/alpkeskin/jev-guardrail/benchmark/internal/bench"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/policy"
)

func TestAUC(t *testing.T) {
	cases := []struct {
		pos, neg []float64
		want     float64
	}{
		{[]float64{0.9, 0.8}, []float64{0.1, 0.2}, 1},
		{[]float64{0.1, 0.2}, []float64{0.9, 0.8}, 0},
		{[]float64{0.5, 0.5}, []float64{0.5, 0.5}, 0.5},
		{[]float64{0.9, 0.3}, []float64{0.5, 0.1}, 0.75},
	}
	for _, c := range cases {
		if got := auc(c.pos, c.neg); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("auc(%v, %v) = %v, want %v", c.pos, c.neg, got, c.want)
		}
	}
}

func TestWilson(t *testing.T) {
	r := newRate(50, 100)
	if r.Value != 0.5 || math.Abs(r.Lo-0.4038) > 1e-3 || math.Abs(r.Hi-0.5962) > 1e-3 {
		t.Fatalf("rate = %+v", r)
	}
	if r := newRate(0, 0); !math.IsNaN(r.Value) {
		t.Fatalf("empty rate = %+v", r)
	}
}

func TestPercentile(t *testing.T) {
	v := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if bench.Percentile(v, 50) != 5 || bench.Percentile(v, 99) != 10 || bench.Percentile(v, 0) != 1 {
		t.Fatal("nearest-rank percentile mismatch")
	}
}

func TestDecisionsMatchPolicy(t *testing.T) {
	pol, err := policy.LoadFile("../../policies/eval-all.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pi := pol.Rules[guardrail.CategoryPromptInjection].Threshold
	if j := decide(pol, map[guardrail.Category]float64{guardrail.CategoryPromptInjection: pi}); j.Decision != guardrail.Blocked {
		t.Fatalf("score at threshold must block: %+v", j)
	}
	if j := decide(pol, map[guardrail.Category]float64{guardrail.CategoryPromptInjection: pi - 0.01}); j.Decision != guardrail.Passed {
		t.Fatalf("score below threshold must pass: %+v", j)
	}
	if j := decide(pol, nil); j.Decision != guardrail.Passed {
		t.Fatalf("no scores must pass: %+v", j)
	}
	for _, label := range bench.Labels() {
		want, err := expectBlock(label, pol)
		if err != nil || want == (label == bench.Benign) {
			t.Errorf("expectBlock(%s) = %v, %v", label, want, err)
		}
	}
}

func TestBenchmarkPolicyReportsEverything(t *testing.T) {
	pol, err := policy.LoadFile("../../policies/benchmark.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range guardrail.Categories() {
		r, ok := pol.Rules[c.Category]
		if !ok || !r.Enabled || r.Action != guardrail.ActionReview || r.Threshold > 0.001 {
			t.Errorf("%s must be an enabled review rule with a ~0 threshold: %+v", c.Category, r)
		}
	}
}
