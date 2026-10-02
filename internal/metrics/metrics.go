// Package metrics exposes Prometheus metrics for the guardrail service.
//
// Label values are always drawn from bounded sets (taxonomy codes, loaded
// policy IDs, route patterns) so caller input can never create unbounded
// time series.
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

const namespace = "guardrail"

// Metrics holds the service's collectors on a private registry. All
// methods are safe to call on a nil *Metrics (they do nothing), which
// keeps instrumentation optional in tests.
type Metrics struct {
	registry *prometheus.Registry

	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
	judgments    *prometheus.CounterVec
	findings     *prometheus.CounterVec
	jevRequests  *prometheus.CounterVec
	jevDuration  *prometheus.HistogramVec
	jevInFlight  prometheus.Gauge
	breakerState *prometheus.GaugeVec
	breakerTrans *prometheus.CounterVec
	policies     prometheus.Gauge
	draining     prometheus.Gauge
}

// New creates and registers all collectors, including Go runtime and
// process collectors and a build_info gauge.
func New(version, commit string) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "http_requests_total",
			Help: "HTTP requests by route, method and status code.",
		}, []string{"route", "method", "code"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "http_request_duration_seconds",
			Help:    "HTTP request latency by route.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"route"}),
		judgments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "judgments_total",
			Help: "Guardrail judgments by judgment, reason code and policy.",
		}, []string{"judgment", "reason_code", "policy_id"}),
		findings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "findings_total",
			Help: "Matched findings by category and policy.",
		}, []string{"category", "policy_id"}),
		jevRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "jev_requests_total",
			Help: "Jev evaluation calls by outcome (success, or a failure/rejection reason).",
		}, []string{"outcome"}),
		jevDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "jev_request_duration_seconds",
			Help:    "Latency of Jev evaluation calls that reached Jev.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"outcome"}),
		jevInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "jev_in_flight_requests",
			Help: "Jev evaluation calls currently in flight.",
		}),
		breakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "jev_circuit_breaker_state",
			Help: "Jev circuit breaker state (1 for the current state).",
		}, []string{"state"}),
		breakerTrans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "jev_circuit_breaker_transitions_total",
			Help: "Jev circuit breaker state transitions by target state.",
		}, []string{"to"}),
		policies: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "policies_loaded",
			Help: "Number of loaded policies.",
		}),
		draining: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "draining",
			Help: "1 while the instance is shutting down.",
		}),
	}
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Build information.",
	}, []string{"version", "commit"})
	buildInfo.WithLabelValues(version, commit).Set(1)

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		buildInfo, m.httpRequests, m.httpDuration, m.judgments, m.findings,
		m.jevRequests, m.jevDuration, m.jevInFlight, m.breakerState, m.breakerTrans,
		m.policies, m.draining,
	)
	for _, s := range []string{"closed", "half_open", "open"} {
		m.breakerState.WithLabelValues(s).Set(0)
	}
	m.breakerState.WithLabelValues("closed").Set(1)
	return m
}

// Handler serves the metrics in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// Registry returns the underlying registry (for tests).
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// ObserveHTTP records one HTTP request.
func (m *Metrics) ObserveHTTP(route, method string, status int, d time.Duration) {
	if m == nil {
		return
	}
	m.httpRequests.WithLabelValues(route, method, strconv.Itoa(status)).Inc()
	m.httpDuration.WithLabelValues(route).Observe(d.Seconds())
}

// ObserveJudgment implements guardrail.JudgmentObserver.
func (m *Metrics) ObserveJudgment(_ context.Context, p guardrail.Policy, j guardrail.Judgment) {
	if m == nil {
		return
	}
	reason := string(guardrail.ReasonNone)
	if j.Reason != nil {
		reason = string(j.Reason.Code)
	}
	m.judgments.WithLabelValues(string(j.Decision), reason, p.ClientID).Inc()
	for _, f := range j.Findings {
		m.findings.WithLabelValues(string(f.Category), p.ClientID).Inc()
	}
}

// ObserveJevRequest records a Jev call. d is zero for calls rejected
// before reaching Jev (circuit open, concurrency limit).
func (m *Metrics) ObserveJevRequest(outcome string, d time.Duration) {
	if m == nil {
		return
	}
	m.jevRequests.WithLabelValues(outcome).Inc()
	if d > 0 {
		m.jevDuration.WithLabelValues(outcome).Observe(d.Seconds())
	}
}

// AddJevInFlight adjusts the in-flight gauge.
func (m *Metrics) AddJevInFlight(delta float64) {
	if m == nil {
		return
	}
	m.jevInFlight.Add(delta)
}

// SetBreakerState records a circuit breaker transition.
func (m *Metrics) SetBreakerState(from, to string) {
	if m == nil {
		return
	}
	m.breakerState.WithLabelValues(from).Set(0)
	m.breakerState.WithLabelValues(to).Set(1)
	m.breakerTrans.WithLabelValues(to).Inc()
}

// SetPoliciesLoaded records the number of loaded policies.
func (m *Metrics) SetPoliciesLoaded(n int) {
	if m == nil {
		return
	}
	m.policies.Set(float64(n))
}

// SetDraining marks the instance as shutting down.
func (m *Metrics) SetDraining() {
	if m == nil {
		return
	}
	m.draining.Set(1)
}
