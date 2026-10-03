package jev

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/resilience"
)

// Outcome labels reported to the Observer.
const (
	OutcomeSuccess      = "success"
	OutcomeTimeout      = "timeout"
	OutcomeUnavailable  = "unavailable"
	OutcomeError        = "error"
	OutcomeCanceled     = "canceled"
	OutcomeCircuitOpen  = "rejected_circuit_open"
	OutcomeLimitReached = "rejected_concurrency_limit"
)

// Observer receives Jev call telemetry. *metrics.Metrics implements it.
type Observer interface {
	ObserveJevRequest(outcome string, d time.Duration)
	AddJevInFlight(delta float64)
}

// ResilientAPI decorates an API with a circuit breaker and a concurrency
// limiter so that a slow or failing Jev cannot exhaust this service:
//
//   - while the breaker is open, calls fail fast with JEV_UNAVAILABLE
//     instead of waiting for the timeout;
//   - at most N calls run concurrently; extra calls wait briefly and then
//     fail fast with JEV_UNAVAILABLE.
//
// Rejections are FAILED judgments, never BLOCKED. Retries are deliberately
// not performed: they would amplify load on a struggling dependency, and
// the caller owns retry/fail-open policy.
type ResilientAPI struct {
	next     API
	breaker  *resilience.Breaker
	limiter  *resilience.Limiter
	observer Observer
}

var _ API = (*ResilientAPI)(nil)

// NewResilientAPI wraps next. breaker, limiter and observer may be nil.
func NewResilientAPI(next API, breaker *resilience.Breaker, limiter *resilience.Limiter, observer Observer) *ResilientAPI {
	return &ResilientAPI{next: next, breaker: breaker, limiter: limiter, observer: observer}
}

// Evaluate implements API.
func (r *ResilientAPI) Evaluate(ctx context.Context, req SystemOneRequest) (SystemOneResponse, error) {
	done := func(resilience.Outcome) {}
	if r.breaker != nil {
		d, err := r.breaker.Allow()
		if err != nil {
			r.observe(OutcomeCircuitOpen, 0)
			return SystemOneResponse{}, guardrail.NewEvaluationError(guardrail.ReasonJevUnavailable, err)
		}
		done = d
	}

	if r.limiter != nil {
		release, err := r.limiter.Acquire(ctx)
		if err != nil {
			done(resilience.Ignore)
			if errors.Is(err, resilience.ErrLimitExceeded) {
				r.observe(OutcomeLimitReached, 0)
				return SystemOneResponse{}, guardrail.NewEvaluationError(guardrail.ReasonJevUnavailable,
					fmt.Errorf("jev concurrency limit (%d) reached", r.limiter.Capacity()))
			}
			r.observe(OutcomeCanceled, 0)
			return SystemOneResponse{}, guardrail.NewEvaluationError(guardrail.ReasonInternalError, err)
		}
		defer release()
	}

	if r.observer != nil {
		r.observer.AddJevInFlight(1)
		defer r.observer.AddJevInFlight(-1)
	}
	start := time.Now()
	resp, err := r.next.Evaluate(ctx, req)
	outcome, bo := classify(err)
	done(bo)
	r.observe(outcome, time.Since(start))
	return resp, err
}

// Ping implements API. Health checks bypass the breaker and limiter so
// readiness reflects Jev itself.
func (r *ResilientAPI) Ping(ctx context.Context) error { return r.next.Ping(ctx) }

func (r *ResilientAPI) observe(outcome string, d time.Duration) {
	if r.observer != nil {
		r.observer.ObserveJevRequest(outcome, d)
	}
}

// classify maps a call result to a metrics outcome and breaker outcome.
// Only dependency failures trip the breaker; caller cancellations don't.
func classify(err error) (string, resilience.Outcome) {
	if err == nil {
		return OutcomeSuccess, resilience.Success
	}
	var se *StatusError
	if errors.As(err, &se) && se.IsRequestSpecific() {
		// Jev is healthy; it rejected this particular request.
		return OutcomeError, resilience.Ignore
	}
	switch guardrail.FailureCode(err) {
	case guardrail.ReasonJevTimeout:
		return OutcomeTimeout, resilience.Failure
	case guardrail.ReasonJevUnavailable:
		return OutcomeUnavailable, resilience.Failure
	case guardrail.ReasonJevError:
		return OutcomeError, resilience.Failure
	default:
		return OutcomeCanceled, resilience.Ignore
	}
}
