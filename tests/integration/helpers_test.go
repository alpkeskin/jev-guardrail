// Package integration exercises the full HTTP pipeline (middleware, policy
// resolution, evaluator, policy engine, response) without a real Jev.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpkeskin/jev-guardrail/internal/api"
	"github.com/alpkeskin/jev-guardrail/internal/auth"
	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/jev"
	"github.com/alpkeskin/jev-guardrail/internal/metrics"
	"github.com/alpkeskin/jev-guardrail/internal/policy"
)

const (
	fixturePolicies = "../fixtures/policies"
	apiKey          = "test-gateway-key-0123456789"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// Lines returns decoded JSON log lines.
func (b *syncBuffer) Lines(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("non-JSON log line %q", line)
		}
		out = append(out, m)
	}
	return out
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	server  *httptest.Server
	logs    *syncBuffer
	metrics *metrics.Metrics
	handler *api.Handler
}

// scrape returns the Prometheus exposition text.
func (h *harness) scrape(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}

func newHarness(t *testing.T, ev guardrail.Evaluator) *harness {
	t.Helper()
	store, err := policy.Load(fixturePolicies)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	keys, err := auth.ParseStaticKeys("litellm:" + apiKey)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	m := metrics.New("test", "abc123")
	svc := guardrail.NewService(ev, guardrail.ThresholdEngine{}, guardrail.WithObserver(m))
	handler := api.NewHandler(svc, 4096, []api.ReadinessCheck{{Name: "evaluator", Check: svc.Ready}})
	srv := httptest.NewServer(api.NewRouter(api.RouterConfig{
		Logger: logger, Handler: handler, Authenticator: keys, Resolver: store, Observer: m,
	}))
	t.Cleanup(srv.Close)
	return &harness{server: srv, logs: logs, metrics: m, handler: handler}
}

type result struct {
	status int
	header http.Header
	raw    string
	body   api.GuardResponse
}

func (h *harness) guard(t *testing.T, body string, headers map[string]string) result {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/v1/guard", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := result{status: resp.StatusCode, header: resp.Header, raw: string(raw)}
	_ = json.Unmarshal(raw, &r.body)
	return r
}

// newFakeJev starts a fake Jev returning per-detector scores. delay makes
// it slow; status != 0 makes it fail.
func newFakeJev(t *testing.T, scores map[string]float64, delay time.Duration, status int) (*httptest.Server, *[]http.Header, *[]jev.EvaluateRequest) {
	t.Helper()
	var mu sync.Mutex
	var headers []http.Header
	var reqs []jev.EvaluateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			return
		}
		var req jev.EvaluateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		headers = append(headers, r.Header.Clone())
		reqs = append(reqs, req)
		mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		resp := jev.EvaluateResponse{Results: []jev.DetectorResult{}}
		for _, d := range req.Detectors {
			s := scores[d]
			resp.Results = append(resp.Results, jev.DetectorResult{Detector: d, Score: &s, Explanation: "JEV-INTERNAL-EXPLANATION"})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &headers, &reqs
}

func newJevEvaluator(t *testing.T, url string, timeout time.Duration) *jev.Evaluator {
	t.Helper()
	c, err := jev.NewClient(jev.ClientConfig{BaseURL: url, APIKey: "jev-test-key", Timeout: timeout, HealthPath: "/health"})
	if err != nil {
		t.Fatal(err)
	}
	return jev.NewEvaluator(c)
}

type panicEvaluator struct{}

func (panicEvaluator) Evaluate(context.Context, guardrail.EvaluationInput, guardrail.Policy) (guardrail.Evaluation, error) {
	panic("evaluator bug")
}

func findings(fs ...guardrail.Finding) *guardrail.MockEvaluator {
	return &guardrail.MockEvaluator{Evaluation: guardrail.Evaluation{Findings: fs}}
}
func requestIDOf(c guardrail.MockCall) string { return reqctx.RequestID(c.Ctx) }
