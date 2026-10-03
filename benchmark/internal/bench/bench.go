// Package bench holds the types shared by the benchmark load generator
// and report: the labeled corpus, per-request results and the mapping from
// corpus labels to the guardrail categories that count as a detection.
package bench

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"sort"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

// Sample is one labeled corpus entry (benchmark/data/samples.jsonl).
type Sample struct {
	ID          string `json:"id"`
	Bucket      string `json:"bucket"`
	Label       string `json:"label"`
	Source      string `json:"source"`
	ContentType string `json:"content_type"`
	Lang        string `json:"lang"`
	Content     string `json:"content"`
}

// Result is the outcome of one guard request (results/<run>/results.jsonl).
type Result struct {
	ID string `json:"id"`
	// ScheduledMS is when the open-loop schedule wanted the request sent,
	// relative to the run start. SentMS is when it was actually sent.
	ScheduledMS float64 `json:"scheduled_ms"`
	SentMS      float64 `json:"sent_ms"`
	// LatencyMS is send -> full response (service time). E2EMS is
	// scheduled -> full response; it includes time spent waiting for a free
	// worker, so a saturated system cannot hide its queueing delay
	// (coordinated omission).
	LatencyMS float64 `json:"latency_ms"`
	E2EMS     float64 `json:"e2e_ms"`
	Status    int     `json:"status"`
	Judgment  string  `json:"judgment,omitempty"`
	Reason    string  `json:"reason,omitempty"`
	// Scores holds every category score the guardrail reported.
	Scores    map[guardrail.Category]float64 `json:"scores,omitempty"`
	RequestID string                         `json:"request_id,omitempty"`
	Error     string                         `json:"error,omitempty"`
}

// OK reports whether the request produced a judgment from Jev.
func (r Result) OK() bool { return r.Status == 200 && r.Error == "" }

// Labels and the categories that count as detecting them. A sample is
// detected when any of its categories matches; which one is reported is
// attribution, measured separately.
var labelCategories = map[string][]guardrail.Category{
	"prompt_attack":   {guardrail.CategoryPromptInjection, guardrail.CategoryJailbreak, guardrail.CategorySystemPromptLeak},
	"harmful_request": {guardrail.CategoryMaliciousInstruction, guardrail.CategoryUnsafeContent},
	"unsafe_response": {guardrail.CategoryMaliciousInstruction, guardrail.CategoryUnsafeContent},
	"pii":             {guardrail.CategorySensitiveData},
	"secret":          {guardrail.CategorySecretExfiltration, guardrail.CategorySensitiveData},
	"malicious_url":   {guardrail.CategoryMaliciousURL},
	"benign":          nil,
}

// Benign is the label of samples that should pass.
const Benign = "benign"

// Labels returns all corpus labels, sorted, with benign last.
func Labels() []string {
	out := make([]string, 0, len(labelCategories))
	for l := range labelCategories {
		if l != Benign {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return append(out, Benign)
}

// CategoriesFor returns the categories that detect label.
func CategoriesFor(label string) ([]guardrail.Category, error) {
	cats, ok := labelCategories[label]
	if !ok {
		return nil, fmt.Errorf("unknown label %q", label)
	}
	return cats, nil
}

// unreliableNegatives are sources whose benign label is known to be wrong
// often enough to distort false positive rates. They stay in the corpus
// file for transparency but are excluded from accuracy and tuning unless
// explicitly included.
var unreliableNegatives = map[string]string{
	// "regular" means "not from a jailbreak community", not "harmless":
	// 8.6% of these prompts in the 80k run start with "Please ignore all
	// previous instructions" or inject a fake system turn.
	"TrustAIRLab/in-the-wild-jailbreak-prompts": "benign prompts frequently contain literal injection text",
}

// Unreliable reports whether a sample's label should not be trusted, and
// why.
func Unreliable(s Sample) (string, bool) {
	if s.Label != Benign {
		return "", false
	}
	why, ok := unreliableNegatives[s.Source]
	return why, ok
}

// Splits. Thresholds are tuned on the calibration split only and reported
// on the held-out test split, so reported accuracy is not inflated by
// tuning on the same samples.
const (
	SplitCalibration = "calibration"
	SplitTest        = "test"
	SplitAll         = "all"
)

// calibrationPercent is the share of samples in the calibration split.
const calibrationPercent = 30

// SplitOf deterministically assigns a sample ID to a split.
func SplitOf(id string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	if h.Sum32()%100 < calibrationPercent {
		return SplitCalibration
	}
	return SplitTest
}

// InSplit reports whether id belongs to split (SplitAll matches all).
func InSplit(id, split string) bool { return split == SplitAll || SplitOf(id) == split }

// ReadJSONL decodes one T per line.
func ReadJSONL[T any](path string, fn func(T) error) error {
	f, err := os.Open(path) //nolint:gosec // operator-provided path
	if err != nil {
		return err
	}
	defer f.Close()
	return DecodeJSONL(f, fn)
}

// DecodeJSONL decodes one T per line from r.
func DecodeJSONL[T any](r io.Reader, fn func(T) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		if len(sc.Bytes()) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err := fn(v); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Percentile returns the p-th percentile (0..100) of sorted values using
// the nearest-rank method. It returns NaN for an empty slice.
func Percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	rank := max(1, int(math.Ceil(p/100*float64(len(sorted)))))
	return sorted[rank-1]
}
