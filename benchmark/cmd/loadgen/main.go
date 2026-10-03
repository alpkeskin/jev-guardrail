// Command loadgen replays the benchmark corpus against a running guardrail
// at a fixed request rate and records one result per sample.
//
//	go run ./benchmark/cmd/loadgen -data benchmark/data/samples.jsonl \
//	    -out benchmark/results/run1/results.jsonl -rps 40
//
// The load is open-loop: request i is due at start + i/rps whether or not
// earlier requests have finished, so a slow system shows up as growing
// end-to-end latency instead of silently lowering the offered load. At
// most -concurrency requests are in flight.
//
// The output is append-only. With -resume, samples that already have a
// successful result are skipped, so an interrupted run can be continued.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/alpkeskin/jev-guardrail/benchmark/internal/bench"
	"github.com/alpkeskin/jev-guardrail/internal/api"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

type config struct {
	data, out, url, clientID, key string
	rps                           float64
	concurrency, limit, offset    int
	timeout                       time.Duration
	resume                        bool
}

func main() {
	var c config
	flag.StringVar(&c.data, "data", "benchmark/data/samples.jsonl", "corpus (JSONL)")
	flag.StringVar(&c.out, "out", "", "results file (JSONL, appended); required")
	flag.StringVar(&c.url, "url", "http://localhost:8080", "guardrail base URL")
	flag.StringVar(&c.clientID, "client-id", "benchmark", "X-Client-ID (policy) to use")
	flag.Float64Var(&c.rps, "rps", 40, "offered load in requests per second")
	flag.IntVar(&c.concurrency, "concurrency", 64, "maximum requests in flight")
	flag.IntVar(&c.limit, "limit", 0, "send at most N samples (0 = all)")
	flag.IntVar(&c.offset, "offset", 0, "skip the first N samples")
	flag.DurationVar(&c.timeout, "timeout", 30*time.Second, "per-request client timeout")
	flag.BoolVar(&c.resume, "resume", false, "skip samples that already have a successful result in -out")
	flag.Parse()
	c.key = os.Getenv("GUARDRAIL_API_KEY")

	if err := run(c); err != nil {
		log.Fatal(err)
	}
}

func run(c config) error {
	switch {
	case c.out == "":
		return errors.New("-out is required")
	case c.key == "":
		return errors.New("GUARDRAIL_API_KEY is required")
	case c.rps <= 0 || c.concurrency <= 0:
		return errors.New("-rps and -concurrency must be positive")
	}

	done := map[string]bool{}
	if c.resume {
		_ = bench.ReadJSONL(c.out, func(r bench.Result) error {
			if r.OK() {
				done[r.ID] = true
			}
			return nil
		})
	}
	var samples []bench.Sample
	i := 0
	err := bench.ReadJSONL(c.data, func(s bench.Sample) error {
		i++
		if i <= c.offset || done[s.ID] || (c.limit > 0 && len(samples) >= c.limit) {
			return nil
		}
		samples = append(samples, s)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	if len(samples) == 0 {
		log.Print("nothing to do")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(c.out), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(c.out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("sending %d samples (%d already done) at %.1f rps, concurrency %d; ETA %s",
		len(samples), len(done), c.rps, c.concurrency, (time.Duration(float64(len(samples))/c.rps) * time.Second).Round(time.Second))

	client := &http.Client{
		Timeout: c.timeout,
		Transport: &http.Transport{
			MaxIdleConns:        c.concurrency,
			MaxIdleConnsPerHost: c.concurrency,
			MaxConnsPerHost:     c.concurrency,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	type job struct {
		s     bench.Sample
		sched time.Time
	}
	jobs := make(chan job)
	results := make(chan bench.Result, c.concurrency)
	start := time.Now()
	ms := func(t time.Time) float64 { return float64(t.Sub(start).Microseconds()) / 1000 }

	var wg sync.WaitGroup
	for w := 0; w < c.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				sent := time.Now()
				r := send(client, c, j.s)
				end := time.Now()
				r.ScheduledMS, r.SentMS = ms(j.sched), ms(sent)
				r.LatencyMS = float64(end.Sub(sent).Microseconds()) / 1000
				r.E2EMS = float64(end.Sub(j.sched).Microseconds()) / 1000
				results <- r
			}
		}()
	}

	// Open-loop dispatcher. Sends block when every worker is busy; the
	// delay is captured by E2EMS because sched is the planned time.
	go func() {
		defer close(jobs)
		interval := time.Duration(float64(time.Second) / c.rps)
		for i, s := range samples {
			sched := start.Add(time.Duration(i) * interval)
			if d := time.Until(sched); d > 0 {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return
				}
			}
			select {
			case jobs <- job{s, sched}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	enc := json.NewEncoder(f)
	prog := newProgress(len(samples))
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case r, ok := <-results:
			if !ok {
				prog.print(time.Since(start), true)
				if ctx.Err() != nil {
					log.Print("interrupted; rerun with -resume to continue")
				}
				return nil
			}
			if err := enc.Encode(r); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
			prog.add(r)
		case <-tick.C:
			prog.print(time.Since(start), false)
		}
	}
}

type guardRequest struct {
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
}

func send(client *http.Client, c config, s bench.Sample) bench.Result {
	r := bench.Result{ID: s.ID}
	body, _ := json.Marshal(guardRequest{Content: s.Content, ContentType: s.ContentType})
	// Not tied to the run context: on interrupt, in-flight requests finish
	// (bounded by the client timeout) so their results are kept.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.url+"/v1/guard", bytes.NewReader(body))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("X-Client-ID", c.clientID)
	resp, err := client.Do(req)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer resp.Body.Close()
	r.Status = resp.StatusCode
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	var gr api.GuardResponse
	if err := json.Unmarshal(raw, &gr); err != nil {
		r.Error = fmt.Sprintf("decode response (HTTP %d): %v", resp.StatusCode, err)
		return r
	}
	r.Judgment, r.RequestID = string(gr.Judgment), gr.RequestID
	if gr.Reason != nil {
		r.Reason = string(gr.Reason.Code)
	}
	if len(gr.Findings) > 0 {
		r.Scores = make(map[guardrail.Category]float64, len(gr.Findings))
		for _, f := range gr.Findings {
			r.Scores[f.Category] = f.Score
		}
	}
	return r
}

// progress tracks a sliding window for periodic status lines.
type progress struct {
	total, n, ok int
	codes        map[string]int
	window       []float64
}

func newProgress(total int) *progress { return &progress{total: total, codes: map[string]int{}} }

func (p *progress) add(r bench.Result) {
	p.n++
	if r.OK() {
		p.ok++
	} else {
		k := r.Reason
		if k == "" {
			k = fmt.Sprintf("HTTP %d", r.Status)
		}
		if r.Error != "" && r.Status == 0 {
			k = "transport"
		}
		p.codes[k]++
	}
	p.window = append(p.window, r.E2EMS)
}

func (p *progress) print(elapsed time.Duration, final bool) {
	w := append([]float64(nil), p.window...)
	sort.Float64s(w)
	p.window = p.window[:0]
	label := "progress"
	if final {
		label = "done"
	}
	log.Printf("%s %d/%d (%.1f%%) ok=%d errors=%v rate=%.1f/s window e2e p50=%.0fms p99=%.0fms",
		label, p.n, p.total, 100*float64(p.n)/float64(p.total), p.ok, p.codes,
		float64(p.n)/elapsed.Seconds(), bench.Percentile(w, 50), bench.Percentile(w, 99))
}
