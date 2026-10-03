// Command report turns a loadgen run into a latency and accuracy report.
//
//	go run ./benchmark/cmd/report -results benchmark/results/run1/results.jsonl \
//	    -policy benchmark/policies/eval-all.yaml
//
// The run records every category score (the benchmark policy reports all
// of them), so judgments are recomputed here with the production
// ThresholdEngine for any policy file. Changing thresholds never requires
// re-running inference.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alpkeskin/jev-guardrail/benchmark/internal/bench"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/policy"
)

func main() {
	data := flag.String("data", "benchmark/data/samples.jsonl", "corpus (JSONL)")
	results := flag.String("results", "", "loadgen results (JSONL); required")
	policyFile := flag.String("policy", "benchmark/policies/eval-all.yaml", "policy whose thresholds and actions are evaluated")
	warmup := flag.Duration("warmup", 10*time.Second, "exclude requests scheduled in the first part of the run from latency stats")
	out := flag.String("out", "", "report directory (default: next to -results)")
	examples := flag.Int("examples", 10, "misclassified examples to list per label")
	split := flag.String("split", bench.SplitAll, "samples to evaluate: all, calibration or test")
	includeUnreliable := flag.Bool("include-unreliable", false, "keep samples whose labels are known to be unreliable")
	flag.Parse()
	if *split != bench.SplitAll && *split != bench.SplitCalibration && *split != bench.SplitTest {
		log.Fatalf("invalid -split %q", *split)
	}
	if *results == "" {
		log.Fatal("-results is required")
	}
	if *out == "" {
		*out = filepath.Dir(*results)
	}
	if err := run(*data, *results, *policyFile, *out, *split, *includeUnreliable, *warmup, *examples); err != nil {
		log.Fatal(err)
	}
}

type row struct {
	s bench.Sample
	r bench.Result
}

func run(dataPath, resultsPath, policyPath, outDir, split string, includeUnreliable bool, warmup time.Duration, nExamples int) error {
	pol, err := policy.LoadFile(policyPath)
	if err != nil {
		return err
	}
	samples := map[string]bench.Sample{}
	if err := bench.ReadJSONL(dataPath, func(s bench.Sample) error { samples[s.ID] = s; return nil }); err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	// A resumed run may hold several results per sample: keep the last
	// successful one, else the last one.
	byID := map[string]bench.Result{}
	var all []bench.Result
	if err := bench.ReadJSONL(resultsPath, func(r bench.Result) error {
		// Latency covers every request; accuracy only the chosen split.
		all = append(all, r)
		if !bench.InSplit(r.ID, split) {
			return nil
		}
		if prev, ok := byID[r.ID]; !ok || r.OK() || !prev.OK() {
			byID[r.ID] = r
		}
		return nil
	}); err != nil {
		return fmt.Errorf("read results: %w", err)
	}
	if len(all) == 0 {
		return errors.New("no results")
	}
	rows := make([]row, 0, len(byID))
	excluded := map[string]int{}
	for id, r := range byID {
		s, ok := samples[id]
		if !ok {
			return fmt.Errorf("result %s is not in the corpus", id)
		}
		if why, bad := bench.Unreliable(s); bad && !includeUnreliable {
			excluded[s.Source+": "+why]++
			continue
		}
		rows = append(rows, row{s, r})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].s.ID < rows[j].s.ID })

	rep := &report{Policy: policyPath, Split: split, Excluded: excluded, Generated: time.Now().UTC().Format(time.RFC3339)}
	rep.Latency = latency(all, samples, warmup)
	rep.Accuracy, rep.examples = accuracy(rows, pol, nExamples)
	rep.Scores = scoreAnalysis(rows)

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return err
	}
	js, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "summary.json"), append(js, '\n'), 0o600); err != nil {
		return err
	}
	md, err := os.Create(filepath.Join(outDir, "report.md")) //nolint:gosec // operator-provided path
	if err != nil {
		return err
	}
	defer md.Close()
	rep.markdown(md, pol)
	log.Printf("wrote %s and %s", filepath.Join(outDir, "report.md"), filepath.Join(outDir, "summary.json"))
	return nil
}

type report struct {
	Policy    string         `json:"policy"`
	Split     string         `json:"split"`
	Excluded  map[string]int `json:"excluded_unreliable"`
	Generated string         `json:"generated"`
	Latency   latencyReport  `json:"latency"`
	Accuracy  accReport      `json:"accuracy"`
	Scores    []labelScores  `json:"scores"`
	examples  map[string][]example
}

// --- Latency -----------------------------------------------------------------

type dist struct {
	N                                   int
	Mean, P50, P90, P95, P99, P999, Max float64
}

func newDist(v []float64) dist {
	if len(v) == 0 {
		return dist{}
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	sum := 0.0
	for _, x := range s {
		sum += x
	}
	return dist{
		N: len(s), Mean: sum / float64(len(s)),
		P50: bench.Percentile(s, 50), P90: bench.Percentile(s, 90), P95: bench.Percentile(s, 95),
		P99: bench.Percentile(s, 99), P999: bench.Percentile(s, 99.9), Max: s[len(s)-1],
	}
}

type latencyReport struct {
	Requests      int            `json:"requests"`
	WarmupS       float64        `json:"warmup_s"`
	Measured      int            `json:"measured"`
	Succeeded     int            `json:"succeeded"`
	DurationS     float64        `json:"duration_s"`
	OfferedRPS    float64        `json:"offered_rps"`
	ThroughputRPS float64        `json:"throughput_rps"`
	Service       dist           `json:"service_ms"`
	EndToEnd      dist           `json:"end_to_end_ms"`
	Failures      map[string]int `json:"failures"`
	ByLength      []namedDist    `json:"by_length"`
	ByType        []namedDist    `json:"by_content_type"`
}

type namedDist struct {
	Name string `json:"name"`
	dist
}

func latency(all []bench.Result, samples map[string]bench.Sample, warmup time.Duration) latencyReport {
	lr := latencyReport{Requests: len(all), Failures: map[string]int{}}
	var service, e2e []float64
	byLen, byType := map[string][]float64{}, map[string][]float64{}
	first, last := math.Inf(1), math.Inf(-1)
	firstSched, lastSched := math.Inf(1), math.Inf(-1)
	for _, r := range all {
		firstSched, lastSched = math.Min(firstSched, r.ScheduledMS), math.Max(lastSched, r.ScheduledMS)
	}
	// The warm-up never exceeds 10% of the run, so short runs keep data.
	wms := math.Min(float64(warmup.Milliseconds()), firstSched+(lastSched-firstSched)/10)
	lr.WarmupS = (wms - firstSched) / 1000
	for _, r := range all {
		first = math.Min(first, r.SentMS)
		last = math.Max(last, r.SentMS+r.LatencyMS)
		if r.OK() {
			lr.Succeeded++
		} else {
			lr.Failures[failureKey(r)]++
		}
		if r.ScheduledMS < wms || !r.OK() {
			continue
		}
		service = append(service, r.LatencyMS)
		e2e = append(e2e, r.E2EMS)
		s := samples[r.ID]
		byLen[lengthBucket(len(s.Content))] = append(byLen[lengthBucket(len(s.Content))], r.LatencyMS)
		byType[s.ContentType] = append(byType[s.ContentType], r.LatencyMS)
	}
	lr.Measured = len(service)
	lr.DurationS = (last - first) / 1000
	if span := (lastSched - firstSched) / 1000; span > 0 {
		lr.OfferedRPS = float64(len(all)-1) / span
	}
	if lr.DurationS > 0 {
		lr.ThroughputRPS = float64(lr.Succeeded) / lr.DurationS
	}
	lr.Service, lr.EndToEnd = newDist(service), newDist(e2e)
	for _, b := range lengthBuckets {
		if v := byLen[b.name]; len(v) > 0 {
			lr.ByLength = append(lr.ByLength, namedDist{b.name, newDist(v)})
		}
	}
	for _, t := range sortedKeys(byType) {
		lr.ByType = append(lr.ByType, namedDist{t, newDist(byType[t])})
	}
	return lr
}

func failureKey(r bench.Result) string {
	switch {
	case r.Status == 0:
		return "transport error"
	case r.Reason != "":
		return fmt.Sprintf("HTTP %d %s", r.Status, r.Reason)
	default:
		return fmt.Sprintf("HTTP %d", r.Status)
	}
}

var lengthBuckets = []struct {
	name string
	max  int
}{{"<200 chars", 200}, {"200-999", 1000}, {"1k-3k", 3000}, {"3k-8k", math.MaxInt}}

func lengthBucket(n int) string {
	for _, b := range lengthBuckets {
		if n < b.max {
			return b.name
		}
	}
	return lengthBuckets[len(lengthBuckets)-1].name
}

// --- Accuracy ----------------------------------------------------------------

type rate struct {
	K, N   int
	Value  float64 `json:"value"`
	Lo, Hi float64 // Wilson 95% interval
}

func newRate(k, n int) rate {
	r := rate{K: k, N: n, Value: math.NaN(), Lo: math.NaN(), Hi: math.NaN()}
	if n == 0 {
		return r
	}
	const z = 1.959964
	p, fn := float64(k)/float64(n), float64(n)
	den := 1 + z*z/fn
	c := (p + z*z/(2*fn)) / den
	h := z * math.Sqrt(p*(1-p)/fn+z*z/(4*fn*fn)) / den
	r.Value, r.Lo, r.Hi = p, math.Max(0, c-h), math.Min(1, c+h)
	return r
}

type accReport struct {
	Evaluated                   int `json:"evaluated"`
	Skipped                     int `json:"skipped_failed_requests"`
	TP, FP, TN, FN              int
	Accuracy, Precision, Recall rate
	FPR                         rate                       `json:"false_positive_rate"`
	F1                          float64                    `json:"f1"`
	ByLabel                     []group                    `json:"by_label"`
	BySource                    []group                    `json:"by_source"`
	ByContentType               []group                    `json:"by_content_type"`
	ByLanguage                  []group                    `json:"by_language_pii"`
	BenignFPByCategory          map[guardrail.Category]int `json:"benign_false_positives_by_category"`
	NotCoveredByPolicy          int                        `json:"positives_not_covered_by_policy"`
}

type group struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	N        int    `json:"n"`
	Blocked  rate   `json:"blocked"`
	Correct  rate   `json:"correct"`
	Attrib   *rate  `json:"attribution,omitempty"`
	expected bool
}

type example struct {
	ID, Source, Content string
	Expected, Got       string
	Top                 string
}

func expectBlock(label string, pol guardrail.Policy) (bool, error) {
	cats, err := bench.CategoriesFor(label)
	if err != nil {
		return false, err
	}
	for _, c := range cats {
		if r, ok := pol.Rules[c]; ok && r.Enabled && r.Action == guardrail.ActionBlock {
			return true, nil
		}
	}
	return false, nil
}

func decide(pol guardrail.Policy, scores map[guardrail.Category]float64) guardrail.Judgment {
	fs := make([]guardrail.Finding, 0, len(scores))
	for c, s := range scores {
		fs = append(fs, guardrail.Finding{Category: c, Score: s})
	}
	return guardrail.ThresholdEngine{}.Decide(context.Background(), pol, fs)
}

type tally struct {
	n, blocked, correct, attribOK, attribN int
	label                                  string
	labels                                 map[string]bool
}

func accuracy(rows []row, pol guardrail.Policy, nExamples int) (accReport, map[string][]example) {
	ar := accReport{BenignFPByCategory: map[guardrail.Category]int{}}
	byLabel, bySource, byType, byLang := map[string]*tally{}, map[string]*tally{}, map[string]*tally{}, map[string]*tally{}
	examples := map[string][]example{}
	get := func(m map[string]*tally, k string) *tally {
		if m[k] == nil {
			m[k] = &tally{labels: map[string]bool{}}
		}
		return m[k]
	}
	for _, x := range rows {
		if !x.r.OK() {
			ar.Skipped++
			continue
		}
		ar.Evaluated++
		want, err := expectBlock(x.s.Label, pol)
		if err != nil {
			log.Fatal(err)
		}
		if !want && x.s.Label != bench.Benign {
			ar.NotCoveredByPolicy++
		}
		j := decide(pol, x.r.Scores)
		got := j.Decision == guardrail.Blocked
		switch {
		case want && got:
			ar.TP++
		case want && !got:
			ar.FN++
		case !want && got:
			ar.FP++
		default:
			ar.TN++
		}
		attrib := -1 // not applicable
		if want && got {
			attrib = 0
			cats, _ := bench.CategoriesFor(x.s.Label)
			for _, c := range cats {
				if j.Reason != nil && string(j.Reason.Code) == string(c) {
					attrib = 1
				}
			}
		}
		if x.s.Label == bench.Benign && got {
			ar.BenignFPByCategory[guardrail.Category(j.Reason.Code)]++
		}
		groups := []*tally{get(byLabel, x.s.Label), get(bySource, x.s.Source), get(byType, x.s.ContentType)}
		if x.s.Label == "pii" {
			groups = append(groups, get(byLang, x.s.Lang))
		}
		for _, t := range groups {
			t.n++
			t.labels[x.s.Label] = true
			if got {
				t.blocked++
			}
			if got == want {
				t.correct++
			}
			if attrib >= 0 {
				t.attribN++
				t.attribOK += attrib
			}
		}
		if got != want && len(examples[x.s.Label]) < nExamples {
			examples[x.s.Label] = append(examples[x.s.Label], example{
				ID: x.s.ID, Source: x.s.Source, Content: x.s.Content,
				Expected: verdict(want), Got: verdict(got), Top: topScores(x.r.Scores, 3),
			})
		}
	}
	n := ar.TP + ar.FP + ar.TN + ar.FN
	ar.Accuracy = newRate(ar.TP+ar.TN, n)
	ar.Precision = newRate(ar.TP, ar.TP+ar.FP)
	ar.Recall = newRate(ar.TP, ar.TP+ar.FN)
	ar.FPR = newRate(ar.FP, ar.FP+ar.TN)
	if p, r := ar.Precision.Value, ar.Recall.Value; p+r > 0 {
		ar.F1 = 2 * p * r / (p + r)
	}
	toGroups := func(m map[string]*tally, order []string) []group {
		var out []group
		for _, k := range order {
			t := m[k]
			if t == nil {
				continue
			}
			g := group{Name: k, N: t.n, Blocked: newRate(t.blocked, t.n), Correct: newRate(t.correct, t.n)}
			ls := sortedKeys(t.labels)
			g.Label = strings.Join(ls, "+")
			if t.attribN > 0 {
				a := newRate(t.attribOK, t.attribN)
				g.Attrib = &a
			}
			out = append(out, g)
		}
		return out
	}
	ar.ByLabel = toGroups(byLabel, bench.Labels())
	ar.BySource = toGroups(bySource, sortedKeys(bySource))
	ar.ByContentType = toGroups(byType, sortedKeys(byType))
	ar.ByLanguage = toGroups(byLang, sortedKeys(byLang))
	return ar, examples
}

func verdict(block bool) string {
	if block {
		return "BLOCKED"
	}
	return "PASSED"
}

func topScores(scores map[guardrail.Category]float64, n int) string {
	type kv struct {
		c guardrail.Category
		s float64
	}
	var xs []kv
	for c, s := range scores {
		xs = append(xs, kv{c, s})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].s > xs[j].s })
	var parts []string
	for i := 0; i < len(xs) && i < n; i++ {
		parts = append(parts, fmt.Sprintf("%s %.2f", xs[i].c, xs[i].s))
	}
	if len(parts) == 0 {
		return "all ~0"
	}
	return strings.Join(parts, ", ")
}

// --- Policy-independent score analysis ---------------------------------------

type labelScores struct {
	Label      string       `json:"label"`
	Positives  int          `json:"positives"`
	Negatives  int          `json:"negatives"`
	AUC        float64      `json:"roc_auc"`
	BestF1     float64      `json:"best_f1"`
	BestThresh float64      `json:"best_f1_threshold"`
	Sweep      []sweepPoint `json:"sweep"`
}

type sweepPoint struct {
	Threshold float64 `json:"threshold"`
	TPR       float64 `json:"tpr"`
	FPR       float64 `json:"fpr"`
}

var sweepThresholds = []float64{0.3, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.99}

// scoreAnalysis measures, per label, how well the max score of the label's
// categories separates its samples from all benign samples.
func scoreAnalysis(rows []row) []labelScores {
	var out []labelScores
	for _, label := range bench.Labels() {
		if label == bench.Benign {
			continue
		}
		cats, _ := bench.CategoriesFor(label)
		score := func(sc map[guardrail.Category]float64) float64 {
			m := 0.0
			for _, c := range cats {
				m = math.Max(m, sc[c])
			}
			return m
		}
		var pos, neg []float64
		for _, x := range rows {
			if !x.r.OK() {
				continue
			}
			switch x.s.Label {
			case label:
				pos = append(pos, score(x.r.Scores))
			case bench.Benign:
				neg = append(neg, score(x.r.Scores))
			}
		}
		if len(pos) == 0 || len(neg) == 0 {
			continue
		}
		ls := labelScores{Label: label, Positives: len(pos), Negatives: len(neg), AUC: auc(pos, neg)}
		for _, t := range sweepThresholds {
			ls.Sweep = append(ls.Sweep, sweepPoint{t, fracAtLeast(pos, t), fracAtLeast(neg, t)})
		}
		for t := 0.01; t <= 1.0001; t += 0.01 {
			tp := fracAtLeast(pos, t) * float64(len(pos))
			fp := fracAtLeast(neg, t) * float64(len(neg))
			fn := float64(len(pos)) - tp
			if f1 := 2 * tp / (2*tp + fp + fn); f1 > ls.BestF1 {
				ls.BestF1, ls.BestThresh = f1, math.Round(t*100)/100
			}
		}
		out = append(out, ls)
	}
	return out
}

func fracAtLeast(v []float64, t float64) float64 {
	k := 0
	for _, x := range v {
		if x >= t-1e-9 {
			k++
		}
	}
	return float64(k) / float64(len(v))
}

// auc is the Mann-Whitney U estimate of ROC AUC, counting ties as half.
func auc(pos, neg []float64) float64 {
	type item struct {
		v   float64
		pos bool
	}
	items := make([]item, 0, len(pos)+len(neg))
	for _, v := range pos {
		items = append(items, item{v, true})
	}
	for _, v := range neg {
		items = append(items, item{v, false})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].v < items[j].v })
	rankSum := 0.0
	for i := 0; i < len(items); {
		j := i
		for j < len(items) && items[j].v == items[i].v {
			j++
		}
		avg := float64(i+j+1) / 2 // average 1-based rank of the tie group
		for k := i; k < j; k++ {
			if items[k].pos {
				rankSum += avg
			}
		}
		i = j
	}
	np, nn := float64(len(pos)), float64(len(neg))
	return (rankSum - np*(np+1)/2) / (np * nn)
}

// --- Markdown ----------------------------------------------------------------

func (rep *report) markdown(w io.Writer, pol guardrail.Policy) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format+"\n", args...) }
	l, a := rep.Latency, rep.Accuracy
	p("# Jev Guardrail benchmark")
	p("")
	p("Generated %s. Accuracy uses the `%s` split; latency uses every request. Decisions evaluated with `%s`:", rep.Generated, rep.Split, rep.Policy)
	p("")
	p("| Category | Enabled | Threshold | Action |")
	p("|---|---|---|---|")
	for _, ci := range guardrail.Categories() {
		r, ok := pol.Rules[ci.Category]
		if !ok {
			p("| `%s` | no | | |", ci.Category)
			continue
		}
		p("| `%s` | %v | %.2f | %s |", ci.Category, r.Enabled, r.Threshold, r.Action)
	}
	p("")
	p("## Summary")
	p("")
	p("| Metric | Value |")
	p("|---|---|")
	p("| Requests | %d (%d succeeded, %.2f%%) |", l.Requests, l.Succeeded, pct(float64(l.Succeeded)/float64(l.Requests)))
	p("| Duration | %s |", (time.Duration(l.DurationS) * time.Second).String())
	p("| Offered / achieved rate | %.1f / %.1f req/s |", l.OfferedRPS, l.ThroughputRPS)
	p("| Service latency p50 / p95 / p99 | %.0f / %.0f / %.0f ms |", l.Service.P50, l.Service.P95, l.Service.P99)
	p("| Accuracy | %s |", fmtRate(a.Accuracy))
	p("| Precision | %s |", fmtRate(a.Precision))
	p("| Recall (detection rate) | %s |", fmtRate(a.Recall))
	p("| False positive rate | %s |", fmtRate(a.FPR))
	p("| F1 | %.3f |", a.F1)
	p("")
	p("Rates show a Wilson 95%% confidence interval. Accuracy figures exclude %d failed requests.", a.Skipped)
	for k, n := range rep.Excluded {
		p("Excluded as unreliable labels: %d samples (%s). Use `-include-unreliable` to keep them.", n, k)
	}
	if a.NotCoveredByPolicy > 0 {
		p("%d positive samples belong to categories this policy does not block; they count as expected PASSED.", a.NotCoveredByPolicy)
	}
	p("")

	p("## Latency")
	p("")
	p("Requests scheduled during the first %.0fs (warm-up) are excluded. *Service* is send → response; *end-to-end* starts at the scheduled send time and includes client-side queueing.", l.WarmupS)
	p("")
	p("| | n | mean | p50 | p90 | p95 | p99 | p99.9 | max |")
	p("|---|---|---|---|---|---|---|---|---|")
	p("%s", distRow("service (ms)", l.Service))
	p("%s", distRow("end-to-end (ms)", l.EndToEnd))
	for _, d := range l.ByLength {
		p("%s", distRow("service, "+d.Name, d.dist))
	}
	for _, d := range l.ByType {
		p("%s", distRow("service, "+d.Name, d.dist))
	}
	p("")
	if len(l.Failures) > 0 {
		p("### Failed requests")
		p("")
		p("| Failure | Count |")
		p("|---|---|")
		for _, k := range sortedKeys(l.Failures) {
			p("| %s | %d |", k, l.Failures[k])
		}
		p("")
	}

	p("## Accuracy")
	p("")
	p("Confusion matrix (positive = should be BLOCKED):")
	p("")
	p("| | Got BLOCKED | Got PASSED |")
	p("|---|---|---|")
	p("| **Expected BLOCKED** | %d (TP) | %d (FN) |", a.TP, a.FN)
	p("| **Expected PASSED** | %d (FP) | %d (TN) |", a.FP, a.TN)
	p("")
	p("### By label")
	p("")
	p("For attack labels *correct* is the detection rate; for `benign` it is 1 − false positive rate. *Attribution* is the share of detected samples whose primary reason is one of the label's categories.")
	p("")
	groupTable(p, a.ByLabel, true)
	p("### By source")
	p("")
	groupTable(p, a.BySource, true)
	p("### By content type")
	p("")
	groupTable(p, a.ByContentType, false)
	if len(a.ByLanguage) > 0 {
		p("### PII detection by language")
		p("")
		groupTable(p, a.ByLanguage, false)
	}
	if len(a.BenignFPByCategory) > 0 {
		p("### What blocks benign samples")
		p("")
		p("| Primary reason | Benign samples blocked |")
		p("|---|---|")
		for _, c := range sortedKeys(a.BenignFPByCategory) {
			p("| `%s` | %d |", c, a.BenignFPByCategory[c])
		}
		p("")
	}

	p("## Score separation")
	p("")
	p("Policy-independent. For each label, the score is the maximum over the label's categories; negatives are all benign samples. TPR/FPR are the shares at or above each threshold.")
	p("")
	header := "| Label | ROC AUC | Best F1 (threshold) |"
	sep := "|---|---|---|"
	for _, t := range sweepThresholds {
		header += fmt.Sprintf(" TPR/FPR @%.2f |", t)
		sep += "---|"
	}
	p("%s", header)
	p("%s", sep)
	for _, s := range rep.Scores {
		line := fmt.Sprintf("| `%s` (%d) | %.3f | %.3f (%.2f) |", s.Label, s.Positives, s.AUC, s.BestF1, s.BestThresh)
		for _, sp := range s.Sweep {
			line += fmt.Sprintf(" %.1f%% / %.1f%% |", pct(sp.TPR), pct(sp.FPR))
		}
		p("%s", line)
	}
	p("")

	if len(rep.examples) > 0 {
		p("## Misclassified examples")
		p("")
		p("Truncated to 200 characters. Look these up by ID in `samples.jsonl`.")
		p("")
		for _, label := range bench.Labels() {
			ex := rep.examples[label]
			if len(ex) == 0 {
				continue
			}
			p("### %s", label)
			p("")
			p("| ID | Source | Expected → got | Top scores | Content |")
			p("|---|---|---|---|---|")
			for _, e := range ex {
				p("| %s | %s | %s → %s | %s | %s |", e.ID, e.Source, e.Expected, e.Got, e.Top, cell(e.Content, 200))
			}
			p("")
		}
	}
}

func groupTable(p func(string, ...any), gs []group, withLabel bool) {
	if withLabel {
		p("| Group | Label | n | Blocked | Correct | Attribution |")
		p("|---|---|---|---|---|---|")
	} else {
		p("| Group | n | Blocked | Correct |")
		p("|---|---|---|---|")
	}
	for _, g := range gs {
		if withLabel {
			attr := "–"
			if g.Attrib != nil {
				attr = fmtRate(*g.Attrib)
			}
			p("| %s | %s | %d | %.1f%% | %s | %s |", g.Name, g.Label, g.N, pct(g.Blocked.Value), fmtRate(g.Correct), attr)
		} else {
			p("| %s | %d | %.1f%% | %s |", g.Name, g.N, pct(g.Blocked.Value), fmtRate(g.Correct))
		}
	}
	p("")
}

func distRow(name string, d dist) string {
	return fmt.Sprintf("| %s | %d | %.0f | %.0f | %.0f | %.0f | %.0f | %.0f | %.0f |",
		name, d.N, d.Mean, d.P50, d.P90, d.P95, d.P99, d.P999, d.Max)
}

func fmtRate(r rate) string {
	if r.N == 0 {
		return "–"
	}
	return fmt.Sprintf("%.2f%% [%.2f–%.2f]", pct(r.Value), pct(r.Lo), pct(r.Hi))
}

func pct(v float64) float64 { return 100 * v }

func cell(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
