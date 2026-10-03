package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

func TestRequestIDPropagation(t *testing.T) {
	jevSrv, headers, reqs := newFakeJev(t, map[string]float64{"prompt_injection": 0.99}, 0, 0)
	h := newHarness(t, newJevEvaluator(t, jevSrv.URL, time.Second))

	r := h.guard(t, injection, map[string]string{"X-Request-ID": "req_123", "X-Client-ID": "acme-production"})

	// -> response (header and judgment body)
	if r.header.Get("X-Request-ID") != "req_123" || r.body.RequestID != "req_123" {
		t.Fatalf("response request id: header=%q body=%q", r.header.Get("X-Request-ID"), r.body.RequestID)
	}
	// -> Jev (header; the System One body has no metadata field)
	if (*headers)[0].Get("X-Request-ID") != "req_123" || len(*reqs) != 1 {
		t.Fatal("request id not forwarded to jev")
	}
	// -> logs: every log line has request_id and client_id.
	var sawCompletion bool
	for _, line := range h.logs.Lines(t) {
		if line["request_id"] != "req_123" || line["client_id"] != "acme-production" {
			t.Errorf("log line missing request/client id: %v", line)
		}
		if line["msg"] == "guardrail evaluation completed" {
			sawCompletion = true
			if line["judgment"] != "BLOCKED" || line["reason_code"] != "PROMPT_INJECTION" || line["policy_id"] != "acme-production" {
				t.Errorf("completion log = %v", line)
			}
		}
	}
	if !sawCompletion {
		t.Fatalf("no completion log: %s", h.logs.String())
	}
}

func TestRequestIDGenerated(t *testing.T) {
	mock := findings()
	h := newHarness(t, mock)
	r1 := h.guard(t, `{"content":"hi"}`, nil)
	r2 := h.guard(t, `{"content":"hi"}`, nil)

	if !strings.HasPrefix(r1.body.RequestID, "req_") || r1.body.RequestID != r1.header.Get("X-Request-ID") {
		t.Fatalf("generated id body=%q header=%q", r1.body.RequestID, r1.header.Get("X-Request-ID"))
	}
	if r1.body.RequestID == r2.body.RequestID {
		t.Fatal("generated ids must be unique")
	}
	// -> context: the evaluator sees the same id.
	if got := requestIDOf(mock.Calls()[0]); got != r1.body.RequestID {
		t.Fatalf("ctx request id = %q, want %q", got, r1.body.RequestID)
	}
	for _, line := range h.logs.Lines(t) {
		if id, _ := line["request_id"].(string); id != r1.body.RequestID && id != r2.body.RequestID {
			t.Errorf("log line has request_id %q", id)
		}
	}
}

func TestContentNeverLogged(t *testing.T) {
	const secret = "SUPER-SECRET-CONTENT-sk-live-1234"
	for _, mock := range []*guardrail.MockEvaluator{
		findings(guardrail.Finding{Category: guardrail.CategorySecretExfiltration, Score: 0.99}),
		{Err: guardrail.NewEvaluationError(guardrail.ReasonJevError, nil)},
	} {
		h := newHarness(t, mock)
		h.guard(t, `{"content":"`+secret+`"}`, nil)
		h.guard(t, `{"content":"`+secret+`","content_type":"bogus"}`, nil)
		h.guard(t, `{"content":"x","content_type":"`+secret+`"}`, nil)
		h.guard(t, `{"content":`+secret+`}`, nil)
		if strings.Contains(h.logs.String(), secret) {
			t.Fatalf("raw content logged:\n%s", h.logs.String())
		}
	}
}

func TestHealthEndpoints(t *testing.T) {
	jevSrv, _, reqs := newFakeJev(t, nil, 0, 0)
	h := newHarness(t, newJevEvaluator(t, jevSrv.URL, time.Second))

	for path, want := range map[string]string{"/health": `"ok"`, "/ready": `"ready"`} {
		resp, err := http.Get(h.server.URL + path) // no credentials needed
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), want) {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	if len(*reqs) != 0 {
		t.Fatal("health endpoints must not run evaluations")
	}
}

func TestPolicyFallbackIsLogged(t *testing.T) {
	h := newHarness(t, findings())
	h.guard(t, `{"content":"hi"}`, map[string]string{"X-Client-ID": "Acme-Production", "X-Request-ID": "req_fallback"})
	h.guard(t, `{"content":"hi"}`, map[string]string{"X-Client-ID": "acme-production", "X-Request-ID": "req_known"})
	for _, line := range h.logs.Lines(t) {
		if line["msg"] != "guardrail evaluation completed" {
			continue
		}
		switch line["request_id"] {
		case "req_fallback":
			if line["policy_fallback"] != true || line["policy_id"] != "default" {
				t.Errorf("fallback not flagged: %v", line)
			}
		case "req_known":
			if _, ok := line["policy_fallback"]; ok {
				t.Errorf("known client flagged as fallback: %v", line)
			}
		}
	}
}
