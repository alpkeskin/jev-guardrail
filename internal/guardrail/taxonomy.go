package guardrail

import "sort"

// Category is a stable, machine-readable guardrail taxonomy identifier.
//
// Categories are part of the public API contract: clients depend on them,
// so existing values must never be renamed or repurposed. New categories
// may be appended.
type Category string

// Security taxonomy.
const (
	CategoryPromptInjection      Category = "PROMPT_INJECTION"
	CategoryJailbreak            Category = "JAILBREAK"
	CategorySystemPromptLeak     Category = "SYSTEM_PROMPT_LEAK"
	CategorySecretExfiltration   Category = "SECRET_EXFILTRATION" //nolint:gosec // taxonomy identifier, not a credential
	CategorySensitiveData        Category = "SENSITIVE_DATA"
	CategoryMaliciousInstruction Category = "MALICIOUS_INSTRUCTION"
	CategoryMaliciousURL         Category = "MALICIOUS_URL"
	CategoryUnsafeContent        Category = "UNSAFE_CONTENT"
)

// CategoryInfo documents a taxonomy category.
type CategoryInfo struct {
	Category Category
	// RuleKey is the canonical policy YAML key that configures the category.
	RuleKey string
	// Description is the stable, human-readable explanation used in
	// findings and reasons. It never contains evaluator output.
	Description string
}

// categories is ordered by priority: when two blocking findings have the
// same score, the one listed first becomes the primary reason.
var categories = []CategoryInfo{
	{CategoryPromptInjection, "prompt_injection", "The content attempts to override existing instructions."},
	{CategoryJailbreak, "jailbreak", "The content attempts to bypass safety restrictions."},
	{CategorySystemPromptLeak, "system_prompt_extraction", "The content attempts to extract or leaks the system prompt."},
	{CategorySecretExfiltration, "secret_exfiltration", "The content attempts to exfiltrate or contains secrets or credentials."},
	{CategorySensitiveData, "sensitive_data", "The content contains sensitive or personal data."},
	{CategoryMaliciousInstruction, "malicious_instruction", "The content contains instructions intended to cause harm."},
	{CategoryMaliciousURL, "malicious_url", "The content contains a malicious or suspicious URL."},
	{CategoryUnsafeContent, "unsafe_content", "The content is unsafe."},
}

// ruleKeyAliases are additional accepted policy keys.
var ruleKeyAliases = map[string]Category{
	"system_prompt_leak": CategorySystemPromptLeak,
}

var (
	categoryIndex = map[Category]int{}
	ruleKeyIndex  = map[string]Category{}
)

func init() {
	for i, c := range categories {
		categoryIndex[c.Category] = i
		ruleKeyIndex[c.RuleKey] = c.Category
	}
	for k, c := range ruleKeyAliases {
		ruleKeyIndex[k] = c
	}
}

// Categories returns all taxonomy categories in priority order.
func Categories() []CategoryInfo {
	out := make([]CategoryInfo, len(categories))
	copy(out, categories)
	return out
}

// IsKnown reports whether c belongs to the taxonomy.
func (c Category) IsKnown() bool {
	_, ok := categoryIndex[c]
	return ok
}

// Description returns the stable description of the category.
func (c Category) Description() string {
	if i, ok := categoryIndex[c]; ok {
		return categories[i].Description
	}
	return ""
}

// priority returns the category's tie-break rank (lower wins).
func (c Category) priority() int {
	if i, ok := categoryIndex[c]; ok {
		return i
	}
	return len(categories)
}

// CategoryForRuleKey maps a policy rule key to its category.
func CategoryForRuleKey(key string) (Category, bool) {
	c, ok := ruleKeyIndex[key]
	return c, ok
}

// ReasonCode is a stable identifier explaining a judgment.
type ReasonCode string

// ReasonNone may be used for PASSED judgments.
const ReasonNone ReasonCode = "NONE"

// Evaluation failure reason codes.
const (
	ReasonInvalidRequest     ReasonCode = "INVALID_REQUEST"
	ReasonInvalidPolicy      ReasonCode = "INVALID_POLICY"
	ReasonJevError           ReasonCode = "JEV_ERROR"
	ReasonJevTimeout         ReasonCode = "JEV_TIMEOUT"
	ReasonJevUnavailable     ReasonCode = "JEV_UNAVAILABLE"
	ReasonUnsupportedContent ReasonCode = "UNSUPPORTED_CONTENT"
	ReasonInternalError      ReasonCode = "INTERNAL_ERROR"
)

// failureMessages are the fixed messages for failure codes. Error strings
// from dependencies are never exposed to callers.
var failureMessages = map[ReasonCode]string{
	ReasonInvalidRequest:     "The request is invalid.",
	ReasonInvalidPolicy:      "The resolved policy is unavailable or invalid.",
	ReasonJevError:           "The evaluation backend returned an invalid response.",
	ReasonJevTimeout:         "The evaluation backend timed out.",
	ReasonJevUnavailable:     "The evaluation backend is unavailable.",
	ReasonUnsupportedContent: "The content is not supported.",
	ReasonInternalError:      "Guardrail evaluation could not be completed.",
}

// FailureCodes returns all failure reason codes, sorted.
func FailureCodes() []ReasonCode {
	out := make([]ReasonCode, 0, len(failureMessages))
	for c := range failureMessages {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// SecurityReason returns the reason code for a security category.
func SecurityReason(c Category) ReasonCode { return ReasonCode(c) }

// IsFailure reports whether the code belongs to the failure taxonomy.
func (r ReasonCode) IsFailure() bool {
	_, ok := failureMessages[r]
	return ok
}
