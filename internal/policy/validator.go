package policy

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidClientID reports whether id is a syntactically valid client ID.
func ValidClientID(id string) bool { return clientIDPattern.MatchString(id) }

// validate converts a parsed document into a Policy, reporting every
// problem found.
func validate(doc document, source string) (Policy, error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if doc.Version != SupportedVersion {
		fail("unsupported version %q (want %q)", doc.Version, SupportedVersion)
	}
	if !ValidClientID(doc.ClientID) {
		fail("invalid client_id %q: must match %s", doc.ClientID, clientIDPattern)
	}
	if len(doc.Rules) == 0 {
		fail("policy must define at least one rule")
	}

	keys := make([]string, 0, len(doc.Rules))
	for k := range doc.Rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rules := make(map[guardrail.Category]Rule, len(doc.Rules))
	seenBy := map[guardrail.Category]string{}
	for _, key := range keys {
		entry := doc.Rules[key]
		cat, ok := guardrail.CategoryForRuleKey(key)
		if !ok {
			fail("rule %q: unknown taxonomy category", key)
			continue
		}
		if prev, dup := seenBy[cat]; dup {
			fail("rule %q: category %s already configured by rule %q", key, cat, prev)
			continue
		}
		seenBy[cat] = key

		r := Rule{Enabled: true, Action: guardrail.Action(entry.Action)}
		if entry.Enabled != nil {
			r.Enabled = *entry.Enabled
		}
		switch {
		case entry.Threshold == nil:
			fail("rule %q: threshold is required", key)
		case math.IsNaN(*entry.Threshold) || *entry.Threshold <= 0 || *entry.Threshold > 1:
			fail("rule %q: threshold %v must be in (0, 1]", key, *entry.Threshold)
		default:
			r.Threshold = *entry.Threshold
		}
		if !r.Action.Valid() {
			fail("rule %q: invalid action %q (want %q or %q)", key, entry.Action, guardrail.ActionBlock, guardrail.ActionReview)
		}
		rules[cat] = r
	}

	if err := errors.Join(errs...); err != nil {
		return Policy{}, fmt.Errorf("policy %s: %w", source, err)
	}
	return Policy{Version: doc.Version, ClientID: doc.ClientID, Rules: rules, Source: source}, nil
}

// Rule is the validated configuration of one category.
type Rule = guardrail.Rule
