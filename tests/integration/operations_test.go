package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/jev"
	"github.com/alpkeskin/jev-guardrail/internal/resilience"
)

func TestMetricsThroughRouter(t *testing.T) {
	h := newHarness(t, findings(guardrail.Finding{Category: guardrail.CategoryPromptInjection, Score: 0.95}))
	h.guard(t, injection, nil)
	h.guard(t, injection, map[string]string{"X-Client-ID": "acme-production"})
	h.guard(t, `{"content":`, nil)
	h.guard(t, injection, map[string]string{"Authorization": ""})

	// Arbitrary paths and methods must not create new label values.
	for _, p := range []string{"/random/abc123", "/v1/guard/../../etc", "/secret-token-xyz"} {
		resp, err := http.Get(h.server.URL + p)
		if err == nil {
			resp.Body.Close()
		}
	}
	req, _ := http.NewRequest("BREW", h.server.URL+"/health", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}

	out := h.scrape(t)
	for _, want := range []string{
		`guardrail_http_requests_total{code="200",method="POST",route="POST /v1/guard"} 2`,
		`guardrail_http_requests_total{code="400",method="POST",route="POST /v1/guard"} 1`,
		`guardrail_http_requests_total{code="401",method="POST",route="POST /v1/guard"} 1`,
		`guardrail_judgments_total{judgment="BLOCKED",policy_id="default",reason_code="PROMPT_INJECTION"} 1`,
		`guardrail_judgments_total{judgment="BLOCKED",policy_id="acme-production",reason_code="PROMPT_INJECTION"} 1`,
		`guardrail_findings_total{category="PROMPT_INJECTION",policy_id="default"} 1`,
		`route="unmatched"`,
		`method="OTHER"`,
		`guardrail_build_info{commit="abc123",version="test"} 1`,
		`guardrail_jev_circuit_breaker_state{state="closed"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
	for _, leak := range []string{"random", "secret-token-xyz", "etc", "BREW"} {
		if strings.Contains(out, leak) {
			t.Errorf("raw request value %q leaked into metric labels", leak)
		}
	}
	// Invalid requests never reach the pipeline, so they are not judgments.
	if strings.Contains(out, `reason_code="INVALID_REQUEST"`) {
		t.Errorf("request validation counted as a judgment")
	}
}

func TestDrainingReadiness(t *testing.T) {
	h := newHarness(t, findings())
	h.handler.SetDraining()

	resp, err := http.Get(h.server.URL + "/ready")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "draining") {
		t.Fatalf("/ready while draining = %d %s", resp.StatusCode, body)
	}
	// Requests are still served while draining.
	if r := h.guard(t, `{"content":"hi"}`, nil); r.status != 200 {
		t.Fatalf("guard while draining = %d", r.status)
	}
}

func TestOpenAPIServed(t *testing.T) {
	h := newHarness(t, findings())
	resp, err := http.Get(h.server.URL + "/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "openapi: 3.1") {
		t.Fatalf("status=%d body=%.40s", resp.StatusCode, body)
	}
}

// TestCircuitBreakerEndToEnd: once Jev keeps failing, callers get an
// immediate FAILED/JEV_UNAVAILABLE instead of waiting for the timeout,
// and the breaker state is visible in metrics.
func TestCircuitBreakerEndToEnd(t *testing.T) {
	jevSrv, _, _ := newFakeJev(t, nil, 300*time.Millisecond, 0)

	h0 := newHarness(t, findings()) // only for its metrics instance
	m := h0.metrics
	client, err := jev.NewClient(jev.ClientConfig{BaseURL: jevSrv.URL, APIKey: "k", Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := resilience.NewBreaker(resilience.BreakerConfig{
		FailureThreshold: 2, OpenTimeout: time.Minute,
		OnStateChange: func(from, to resilience.State) { m.SetBreakerState(from.String(), to.String()) },
	})
	l, _ := resilience.NewLimiter(10, 10*time.Millisecond)
	ev := jev.NewEvaluator(jev.NewResilientAPI(client, b, l, m))
	h := newHarness(t, ev)

	for i := 0; i < 2; i++ {
		if r := h.guard(t, injection, nil); r.body.Reason == nil || r.body.Reason.Code != "JEV_TIMEOUT" {
			t.Fatalf("call %d: %s", i, r.raw)
		}
	}
	start := time.Now()
	r := h.guard(t, injection, nil)
	if r.status != 503 || r.body.Judgment != guardrail.Failed || r.body.Reason.Code != "JEV_UNAVAILABLE" {
		t.Fatalf("open breaker: %d %s", r.status, r.raw)
	}
	if time.Since(start) > 40*time.Millisecond {
		t.Fatalf("open breaker did not fail fast (%s)", time.Since(start))
	}
	out := h0.scrape(t)
	for _, want := range []string{
		`guardrail_jev_circuit_breaker_state{state="open"} 1`,
		`guardrail_jev_circuit_breaker_state{state="closed"} 0`,
		`guardrail_jev_requests_total{outcome="rejected_circuit_open"} 1`,
		`guardrail_jev_requests_total{outcome="timeout"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}
