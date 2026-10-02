package jev

import (
	"fmt"
	"math"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

// detectorByCategory is the single translation table between the
// service's stable taxonomy and Jev's detector names. If Jev renames a
// detector, only this table changes; the public taxonomy does not.
var detectorByCategory = map[guardrail.Category]string{
	guardrail.CategoryPromptInjection:      "prompt_injection",
	guardrail.CategoryJailbreak:            "jailbreak",
	guardrail.CategorySystemPromptLeak:     "system_prompt_leakage",
	guardrail.CategorySecretExfiltration:   "secret_leakage",
	guardrail.CategorySensitiveData:        "pii",
	guardrail.CategoryMaliciousInstruction: "harmful_instructions",
	guardrail.CategoryMaliciousURL:         "malicious_url",
	guardrail.CategoryUnsafeContent:        "unsafe_content",
}

var categoryByDetector = func() map[string]guardrail.Category {
	m := make(map[string]guardrail.Category, len(detectorByCategory))
	for c, d := range detectorByCategory {
		m[d] = c
	}
	return m
}()

// DetectorFor returns the Jev detector for a category.
func DetectorFor(c guardrail.Category) (string, bool) {
	d, ok := detectorByCategory[c]
	return d, ok
}

// MapResults converts Jev results into taxonomy findings. Detectors that
// do not map to the taxonomy are dropped (and returned as ignored); a
// missing or out-of-range score makes the whole response invalid.
// Finding.Matched is left false: matching is the policy engine's job.
func MapResults(results []DetectorResult) (findings []guardrail.Finding, ignored []string, err error) {
	findings = make([]guardrail.Finding, 0, len(results))
	for _, r := range results {
		cat, ok := categoryByDetector[r.Detector]
		if !ok {
			ignored = append(ignored, r.Detector)
			continue
		}
		if r.Score == nil {
			return nil, nil, fmt.Errorf("detector %q: missing score", r.Detector)
		}
		s := *r.Score
		if math.IsNaN(s) || s < 0 || s > 1 {
			return nil, nil, fmt.Errorf("detector %q: score %v out of range [0,1]", r.Detector, s)
		}
		findings = append(findings, guardrail.Finding{
			Category: cat,
			Score:    s,
			Reason:   cat.Description(),
		})
	}
	return findings, ignored, nil
}
