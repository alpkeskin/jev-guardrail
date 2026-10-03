package metrics

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

func TestNilMetricsAreNoOps(t *testing.T) {
	var m *Metrics
	m.ObserveHTTP("r", "GET", 200, time.Second)
	m.ObserveJudgment(context.Background(), guardrail.Policy{}, guardrail.Judgment{Decision: guardrail.Passed})
	m.ObserveJevRequest("success", time.Second)
	m.AddJevInFlight(1)
	m.SetBreakerState("closed", "open")
	m.SetPoliciesLoaded(3)
	m.SetDraining()
}

func TestMetricsExposition(t *testing.T) {
	m := New("1.2.3", "deadbeef")
	m.SetPoliciesLoaded(3)
	m.ObserveJudgment(context.Background(), guardrail.Policy{ClientID: "default"}, guardrail.Judgment{Decision: guardrail.Passed})
	m.ObserveJudgment(context.Background(), guardrail.Policy{ClientID: "acme"}, guardrail.FailedJudgment(guardrail.ReasonJevTimeout))
	m.ObserveJevRequest("rejected_circuit_open", 0)
	m.ObserveJevRequest("success", 20*time.Millisecond)
	m.AddJevInFlight(2)
	m.AddJevInFlight(-1)
	m.SetBreakerState("closed", "open")
	m.SetDraining()

	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	out := w.Body.String()
	for _, want := range []string{
		`guardrail_build_info{commit="deadbeef",version="1.2.3"} 1`,
		`guardrail_policies_loaded 3`,
		`guardrail_judgments_total{judgment="PASSED",policy_id="default",reason_code="NONE"} 1`,
		`guardrail_judgments_total{judgment="FAILED",policy_id="acme",reason_code="JEV_TIMEOUT"} 1`,
		`guardrail_jev_requests_total{outcome="rejected_circuit_open"} 1`,
		`guardrail_jev_request_duration_seconds_count{outcome="success"} 1`,
		`guardrail_jev_in_flight_requests 1`,
		`guardrail_jev_circuit_breaker_state{state="open"} 1`,
		`guardrail_jev_circuit_breaker_state{state="closed"} 0`,
		`guardrail_jev_circuit_breaker_transitions_total{to="open"} 1`,
		`guardrail_draining 1`,
		`go_goroutines`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	// Rejected calls never reached Jev and must not skew latency.
	if strings.Contains(out, `guardrail_jev_request_duration_seconds_count{outcome="rejected_circuit_open"}`) {
		t.Error("rejections recorded in latency histogram")
	}
}
