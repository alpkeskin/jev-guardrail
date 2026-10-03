package jev

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/resilience"
)

type recordingObserver struct {
	mu       sync.Mutex
	outcomes map[string]int
	inFlight float64
	maxSeen  float64
}

func (o *recordingObserver) ObserveJevRequest(outcome string, _ time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.outcomes == nil {
		o.outcomes = map[string]int{}
	}
	o.outcomes[outcome]++
}

func (o *recordingObserver) AddJevInFlight(d float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.inFlight += d
	if o.inFlight > o.maxSeen {
		o.maxSeen = o.inFlight
	}
}

func (o *recordingObserver) count(outcome string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcomes[outcome]
}

func statusServer(t *testing.T, status *atomic.Int32, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if s := status.Load(); s != 200 {
			w.WriteHeader(int(s))
			return
		}
		_, _ = w.Write([]byte(`{"answers":{"jailbreak":{"type":"noul","noul":0.1}}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResilientBreakerFailsFast(t *testing.T) {
	var status, hits atomic.Int32
	status.Store(503)
	srv := statusServer(t, &status, &hits)

	b, _ := resilience.NewBreaker(resilience.BreakerConfig{FailureThreshold: 3, OpenTimeout: 50 * time.Millisecond})
	obs := &recordingObserver{}
	ev := NewEvaluator(NewResilientAPI(newTestClient(t, srv.URL, time.Second), b, nil, obs))
	pol := policyWith(guardrail.CategoryJailbreak)
	in := guardrail.EvaluationInput{Content: "x"}

	for i := 0; i < 3; i++ {
		_, err := ev.Evaluate(context.Background(), in, pol)
		if guardrail.FailureCode(err) != guardrail.ReasonJevUnavailable {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	// Breaker is open: no request reaches Jev and failure is immediate.
	_, err := ev.Evaluate(context.Background(), in, pol)
	if guardrail.FailureCode(err) != guardrail.ReasonJevUnavailable || !errors.Is(err, resilience.ErrOpen) {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 3 || obs.count(OutcomeCircuitOpen) != 1 || obs.count(OutcomeUnavailable) != 3 {
		t.Fatalf("hits=%d outcomes=%v", hits.Load(), obs.outcomes)
	}

	// Jev recovers: after the open timeout a probe closes the breaker.
	status.Store(200)
	time.Sleep(60 * time.Millisecond)
	if _, err := ev.Evaluate(context.Background(), in, pol); err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if b.State() != resilience.Closed {
		t.Fatalf("state = %s", b.State())
	}
}

func TestResilientRequestSpecificErrorsDoNotTrip(t *testing.T) {
	for _, code := range []int{400, 413, 422} {
		var status, hits atomic.Int32
		status.Store(int32(code))
		srv := statusServer(t, &status, &hits)
		b, _ := resilience.NewBreaker(resilience.BreakerConfig{FailureThreshold: 2, OpenTimeout: time.Minute})
		api := NewResilientAPI(newTestClient(t, srv.URL, time.Second), b, nil, nil)
		for i := 0; i < 5; i++ {
			_, err := api.Evaluate(context.Background(), SystemOneRequest{})
			if guardrail.FailureCode(err) != guardrail.ReasonJevError {
				t.Fatalf("%d: %v", code, err)
			}
		}
		if b.State() != resilience.Closed {
			t.Fatalf("HTTP %d tripped the breaker", code)
		}
	}
	// Configuration errors (401) do trip it.
	var status, hits atomic.Int32
	status.Store(401)
	srv := statusServer(t, &status, &hits)
	b, _ := resilience.NewBreaker(resilience.BreakerConfig{FailureThreshold: 2, OpenTimeout: time.Minute})
	api := NewResilientAPI(newTestClient(t, srv.URL, time.Second), b, nil, nil)
	for i := 0; i < 2; i++ {
		_, _ = api.Evaluate(context.Background(), SystemOneRequest{})
	}
	if b.State() != resilience.Open {
		t.Fatal("401 must trip the breaker")
	}
}

func TestResilientCallerCancelDoesNotTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body so the server notices the client disconnecting.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	b, _ := resilience.NewBreaker(resilience.BreakerConfig{FailureThreshold: 1, OpenTimeout: time.Minute})
	api := NewResilientAPI(newTestClient(t, srv.URL, time.Second), b, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	// The caller's own deadline (shorter than the Jev timeout) expires.
	_, err := api.Evaluate(ctx, SystemOneRequest{})
	if err == nil || b.State() != resilience.Closed {
		t.Fatalf("err=%v state=%s", err, b.State())
	}
}

func TestResilientConcurrencyLimit(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		_, _ = w.Write([]byte(`{"answers":{}}`))
	}))
	defer srv.Close()
	defer close(release)

	l, _ := resilience.NewLimiter(2, 10*time.Millisecond)
	obs := &recordingObserver{}
	api := NewResilientAPI(newTestClient(t, srv.URL, 5*time.Second), nil, l, obs)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = api.Evaluate(context.Background(), SystemOneRequest{}) }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	_, err := api.Evaluate(context.Background(), SystemOneRequest{})
	if guardrail.FailureCode(err) != guardrail.ReasonJevUnavailable || obs.count(OutcomeLimitReached) != 1 {
		t.Fatalf("err=%v outcomes=%v", err, obs.outcomes)
	}
	if hits.Load() != 2 {
		t.Fatalf("rejected call reached jev (hits=%d)", hits.Load())
	}
	release <- struct{}{}
	release <- struct{}{}
	wg.Wait()
	if obs.maxSeen != 2 || obs.inFlight != 0 {
		t.Fatalf("in-flight max=%v final=%v", obs.maxSeen, obs.inFlight)
	}
}

func TestResilientPingBypassesBreaker(t *testing.T) {
	var status, hits atomic.Int32
	status.Store(200)
	srv := statusServer(t, &status, &hits)
	b, _ := resilience.NewBreaker(resilience.BreakerConfig{FailureThreshold: 1, OpenTimeout: time.Minute})
	done, _ := b.Allow()
	done(resilience.Failure)
	api := NewResilientAPI(newTestClient(t, srv.URL, time.Second), b, nil, nil)
	if err := api.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}
