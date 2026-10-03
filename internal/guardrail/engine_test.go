package guardrail

import (
	"context"
	"math"
	"testing"
)

func testPolicy() Policy {
	return Policy{
		Version:  "1",
		ClientID: "test",
		Rules: map[Category]Rule{
			CategoryPromptInjection:  {Enabled: true, Threshold: 0.80, Action: ActionBlock},
			CategoryJailbreak:        {Enabled: true, Threshold: 0.85, Action: ActionBlock},
			CategorySystemPromptLeak: {Enabled: true, Threshold: 0.80, Action: ActionBlock},
			CategorySensitiveData:    {Enabled: true, Threshold: 0.90, Action: ActionReview},
			CategoryMaliciousURL:     {Enabled: false, Threshold: 0.10, Action: ActionBlock},
		},
	}
}

func TestEngineDecide(t *testing.T) {
	e := ThresholdEngine{}
	ctx := context.Background()

	tests := []struct {
		name         string
		findings     []Finding
		wantDecision Decision
		wantReason   ReasonCode
		wantMatched  []Category
	}{
		{"no findings", nil, Passed, "", nil},
		{"clean scores", []Finding{
			{Category: CategoryPromptInjection, Score: 0.10},
			{Category: CategoryJailbreak, Score: 0.02},
		}, Passed, "", nil},
		{"prompt injection", []Finding{
			{Category: CategoryPromptInjection, Score: 0.94},
			{Category: CategoryJailbreak, Score: 0.10},
		}, Blocked, ReasonCode(CategoryPromptInjection), []Category{CategoryPromptInjection}},
		{"threshold is inclusive", []Finding{
			{Category: CategoryPromptInjection, Score: 0.80},
		}, Blocked, ReasonCode(CategoryPromptInjection), []Category{CategoryPromptInjection}},
		{"multiple violations, highest score is primary", []Finding{
			{Category: CategorySystemPromptLeak, Score: 0.91},
			{Category: CategoryPromptInjection, Score: 0.97},
		}, Blocked, ReasonCode(CategoryPromptInjection), []Category{CategoryPromptInjection, CategorySystemPromptLeak}},
		{"tie broken by taxonomy order", []Finding{
			{Category: CategorySystemPromptLeak, Score: 0.90},
			{Category: CategoryPromptInjection, Score: 0.90},
		}, Blocked, ReasonCode(CategoryPromptInjection), []Category{CategoryPromptInjection, CategorySystemPromptLeak}},
		{"review action reports but passes", []Finding{
			{Category: CategorySensitiveData, Score: 0.95},
		}, Passed, "", []Category{CategorySensitiveData}},
		{"review never becomes primary reason", []Finding{
			{Category: CategorySensitiveData, Score: 0.99},
			{Category: CategoryJailbreak, Score: 0.86},
		}, Blocked, ReasonCode(CategoryJailbreak), []Category{CategorySensitiveData, CategoryJailbreak}},
		{"disabled rule ignored", []Finding{
			{Category: CategoryMaliciousURL, Score: 0.99},
		}, Passed, "", nil},
		{"category without rule ignored", []Finding{
			{Category: CategoryUnsafeContent, Score: 0.99},
		}, Passed, "", nil},
		{"unknown category ignored", []Finding{
			{Category: "SOMETHING_ELSE", Score: 0.99},
		}, Passed, "", nil},
		{"duplicates keep max score", []Finding{
			{Category: CategoryPromptInjection, Score: 0.95},
			{Category: CategoryPromptInjection, Score: 0.10},
		}, Blocked, ReasonCode(CategoryPromptInjection), []Category{CategoryPromptInjection}},
		{"invalid score fails", []Finding{
			{Category: CategoryPromptInjection, Score: math.NaN()},
		}, Failed, ReasonInternalError, nil},
		{"out of range score fails", []Finding{
			{Category: CategoryPromptInjection, Score: 1.5},
		}, Failed, ReasonInternalError, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j := e.Decide(ctx, testPolicy(), tc.findings)
			if j.Decision != tc.wantDecision {
				t.Fatalf("decision = %s, want %s", j.Decision, tc.wantDecision)
			}
			switch {
			case tc.wantReason == "" && j.Reason != nil:
				t.Fatalf("unexpected reason %+v", j.Reason)
			case tc.wantReason != "" && (j.Reason == nil || j.Reason.Code != tc.wantReason):
				t.Fatalf("reason = %+v, want %s", j.Reason, tc.wantReason)
			}
			if len(j.Findings) != len(tc.wantMatched) {
				t.Fatalf("findings = %+v, want %v", j.Findings, tc.wantMatched)
			}
			for i, f := range j.Findings {
				if f.Category != tc.wantMatched[i] || !f.Matched || f.Reason == "" {
					t.Fatalf("finding %d = %+v, want matched %s", i, f, tc.wantMatched[i])
				}
			}
		})
	}
}

func TestEngineReasonMessageIsStable(t *testing.T) {
	j := ThresholdEngine{}.Decide(context.Background(), testPolicy(), []Finding{
		{Category: CategoryPromptInjection, Score: 0.9, Reason: "jev internal explanation"},
	})
	if j.Reason.Message != CategoryPromptInjection.Description() || j.Findings[0].Reason != CategoryPromptInjection.Description() {
		t.Fatalf("evaluator text leaked: %+v", j)
	}
}

func TestTaxonomy(t *testing.T) {
	seenKeys := map[string]bool{}
	for _, c := range Categories() {
		if !c.Category.IsKnown() || c.Description == "" || c.RuleKey == "" {
			t.Errorf("incomplete category %+v", c)
		}
		if string(c.Category) != toUpper(string(c.Category)) {
			t.Errorf("category %s is not uppercase", c.Category)
		}
		if seenKeys[c.RuleKey] {
			t.Errorf("duplicate rule key %s", c.RuleKey)
		}
		seenKeys[c.RuleKey] = true
		if got, ok := CategoryForRuleKey(c.RuleKey); !ok || got != c.Category {
			t.Errorf("CategoryForRuleKey(%s) = %s", c.RuleKey, got)
		}
		if SecurityReason(c.Category).IsFailure() {
			t.Errorf("security reason %s classified as failure", c.Category)
		}
	}
	if len(Categories()) != 8 {
		t.Fatalf("taxonomy has %d categories, want 8", len(Categories()))
	}
}

func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
