// Command tune picks policy thresholds from a benchmark run.
//
//	go run ./benchmark/cmd/tune -results benchmark/results/<run>/results.jsonl \
//	    -policy policies/default.yaml -target-fpr 0.03
//
// It uses the calibration split only, so the test split stays unseen for
// reporting. The policy file supplies which categories are enabled and
// their actions; only thresholds are chosen.
//
// Method (false-positive budgeting): every blocking category gets the same
// budget b of benign false positives. Its threshold is the lowest grid
// value whose benign false positive rate is at most b. The largest b whose
// combined false positive rate (a benign sample blocked by any category)
// stays within -target-fpr wins. Budgets depend only on benign samples, so
// the result does not favor the categories with the most attack samples.
package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"sort"

	"github.com/alpkeskin/jev-guardrail/benchmark/internal/bench"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/policy"
)

func main() {
	data := flag.String("data", "benchmark/data/samples.jsonl", "corpus (JSONL)")
	results := flag.String("results", "", "loadgen results (JSONL); required")
	policyFile := flag.String("policy", "policies/default.yaml", "policy whose enabled categories and actions are kept")
	target := flag.Float64("target-fpr", 0.03, "maximum combined benign false positive rate")
	minT := flag.Float64("min-threshold", 0.10, "lowest threshold allowed")
	maxT := flag.Float64("max-threshold", 0.99, "highest threshold allowed")
	includeUnreliable := flag.Bool("include-unreliable", false, "keep samples whose labels are known to be unreliable")
	flag.Parse()
	if *results == "" {
		log.Fatal("-results is required")
	}
	if err := run(*data, *results, *policyFile, *target, *minT, *maxT, *includeUnreliable); err != nil {
		log.Fatal(err)
	}
}

type scored struct {
	label  string
	scores map[guardrail.Category]float64
}

func run(dataPath, resultsPath, policyPath string, target, minT, maxT float64, includeUnreliable bool) error {
	pol, err := policy.LoadFile(policyPath)
	if err != nil {
		return err
	}
	labels := map[string]string{}
	if err := bench.ReadJSONL(dataPath, func(s bench.Sample) error {
		if _, bad := bench.Unreliable(s); !bad || includeUnreliable {
			labels[s.ID] = s.Label
		}
		return nil
	}); err != nil {
		return err
	}
	byID := map[string]scored{}
	if err := bench.ReadJSONL(resultsPath, func(r bench.Result) error {
		if _, known := labels[r.ID]; known && r.OK() && bench.SplitOf(r.ID) == bench.SplitCalibration {
			byID[r.ID] = scored{labels[r.ID], r.Scores}
		}
		return nil
	}); err != nil {
		return err
	}
	var benign, attacks []scored
	for _, s := range byID {
		if s.label == bench.Benign {
			benign = append(benign, s)
		} else {
			attacks = append(attacks, s)
		}
	}
	if len(benign) == 0 {
		return fmt.Errorf("no benign calibration samples in %s", resultsPath)
	}

	var cats []guardrail.Category
	for _, c := range pol.EnabledCategories() {
		if pol.Rules[c].Action == guardrail.ActionBlock {
			cats = append(cats, c)
		}
	}
	grid := []float64{}
	for t := math.Round(minT*100) / 100; t <= maxT+1e-9; t += 0.01 {
		grid = append(grid, math.Round(t*100)/100)
	}
	// thresholdFor returns the lowest grid threshold with benign FPR <= b.
	thresholdFor := func(c guardrail.Category, b float64) float64 {
		for _, t := range grid {
			if fpr(benign, c, t) <= b {
				return t
			}
		}
		return maxT
	}
	thresholds := func(b float64) map[guardrail.Category]float64 {
		m := map[guardrail.Category]float64{}
		for _, c := range cats {
			m[c] = thresholdFor(c, b)
		}
		return m
	}

	best := thresholds(0)
	for b := 0.0; b <= target+1e-12; b += 0.0005 {
		th := thresholds(b)
		if combinedFPR(benign, th) <= target {
			best = th
		}
	}

	fmt.Printf("# Calibration split: %d benign, %d attack samples. Target combined FPR %.2f%%.\n",
		len(benign), len(attacks), 100*target)
	fmt.Printf("# Combined benign FPR at these thresholds: %.2f%%\n#\n", 100*combinedFPR(benign, best))
	fmt.Printf("# %-24s %9s %12s\n", "category", "threshold", "benign FPR")
	for _, c := range cats {
		fmt.Printf("# %-24s %9.2f %11.2f%%\n", c, best[c], 100*fpr(benign, c, best[c]))
	}
	fmt.Printf("#\n# %-16s %8s %10s\n", "label", "n", "detected")
	byLabel := map[string][]scored{}
	for _, s := range attacks {
		byLabel[s.label] = append(byLabel[s.label], s)
	}
	for _, l := range sortedKeys(byLabel) {
		xs := byLabel[l]
		fmt.Printf("# %-16s %8d %9.2f%%\n", l, len(xs), 100*float64(countBlocked(xs, best))/float64(len(xs)))
	}
	fmt.Println()
	fmt.Println("rules:")
	for _, ci := range guardrail.Categories() {
		r, ok := pol.Rules[ci.Category]
		if !ok {
			continue
		}
		t := r.Threshold
		if v, tuned := best[ci.Category]; tuned {
			t = v
		}
		fmt.Printf("  %s:\n    enabled: %v\n    threshold: %.2f\n    action: %s\n", ci.RuleKey, r.Enabled, t, r.Action)
	}
	return nil
}

func fpr(benign []scored, c guardrail.Category, t float64) float64 {
	k := 0
	for _, s := range benign {
		if s.scores[c] >= t {
			k++
		}
	}
	return float64(k) / float64(len(benign))
}

func blocked(s scored, th map[guardrail.Category]float64) bool {
	for c, t := range th {
		if s.scores[c] >= t {
			return true
		}
	}
	return false
}

func countBlocked(xs []scored, th map[guardrail.Category]float64) int {
	k := 0
	for _, s := range xs {
		if blocked(s, th) {
			k++
		}
	}
	return k
}

func combinedFPR(benign []scored, th map[guardrail.Category]float64) float64 {
	return float64(countBlocked(benign, th)) / float64(len(benign))
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
