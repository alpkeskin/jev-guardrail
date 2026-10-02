package guardrail

import (
	"context"
	"math"
	"sort"
)

// PolicyEngine turns findings into a judgment according to a policy.
type PolicyEngine interface {
	Decide(ctx context.Context, policy Policy, findings []Finding) Judgment
}

// ThresholdEngine is the default PolicyEngine.
//
// A finding matches when its category has an enabled rule and its score is
// at or above the rule's threshold. If any matched rule has action "block"
// the judgment is BLOCKED and the primary reason is the highest-scoring
// blocking finding (ties broken by taxonomy order). Otherwise the judgment
// is PASSED; matches of "review" rules are still reported as findings.
//
// Only matched findings are returned. Findings for unknown categories or
// categories without an enabled rule are ignored.
type ThresholdEngine struct{}

// Decide implements PolicyEngine.
func (ThresholdEngine) Decide(_ context.Context, policy Policy, findings []Finding) Judgment {
	// Deduplicate by category, keeping the highest score.
	best := make(map[Category]Finding, len(findings))
	for _, f := range findings {
		if math.IsNaN(f.Score) || f.Score < 0 || f.Score > 1 {
			// Evaluators must emit scores in [0,1]; anything else means the
			// evaluation is unreliable.
			return FailedJudgment(ReasonInternalError)
		}
		if !f.Category.IsKnown() {
			continue
		}
		if cur, ok := best[f.Category]; !ok || f.Score > cur.Score {
			best[f.Category] = f
		}
	}

	matched := make([]Finding, 0, len(best))
	var primary *Finding
	for cat, f := range best {
		rule, ok := policy.Rules[cat]
		if !ok || !rule.Enabled || f.Score < rule.Threshold {
			continue
		}
		f.Matched = true
		f.Reason = cat.Description()
		matched = append(matched, f)
		if rule.Action == ActionBlock && (primary == nil || outranks(f, *primary)) {
			p := f
			primary = &p
		}
	}
	sort.Slice(matched, func(i, j int) bool { return outranks(matched[i], matched[j]) })

	if primary == nil {
		return Judgment{Decision: Passed, Findings: matched}
	}
	return Judgment{
		Decision: Blocked,
		Reason:   &Reason{Code: SecurityReason(primary.Category), Message: primary.Category.Description()},
		Findings: matched,
	}
}

// outranks orders findings by score descending, then taxonomy priority.
func outranks(a, b Finding) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.Category.priority() < b.Category.priority()
}
