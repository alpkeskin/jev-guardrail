// Package resilience provides dependency-protection primitives: a circuit
// breaker and a concurrency limiter.
package resilience

import (
	"errors"
	"sync"
	"time"
)

// State is a circuit breaker state.
type State int

const (
	// Closed: requests flow; consecutive failures are counted.
	Closed State = iota
	// HalfOpen: a limited number of probe requests test recovery.
	HalfOpen
	// Open: requests are rejected immediately.
	Open
)

func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case HalfOpen:
		return "half_open"
	case Open:
		return "open"
	}
	return "unknown"
}

// Outcome classifies the result of a guarded call.
type Outcome int

const (
	// Success resets the failure count (and closes a half-open breaker).
	Success Outcome = iota
	// Failure counts towards opening the breaker.
	Failure
	// Ignore neither succeeds nor fails (e.g. the caller canceled).
	Ignore
)

// ErrOpen is returned by Allow when the breaker rejects a call.
var ErrOpen = errors.New("circuit breaker is open")

// BreakerConfig configures a Breaker.
type BreakerConfig struct {
	// FailureThreshold is the number of consecutive failures that opens
	// the breaker. Must be >= 1.
	FailureThreshold int
	// OpenTimeout is how long the breaker stays open before probing.
	OpenTimeout time.Duration
	// HalfOpenMaxRequests is the number of concurrent probes allowed while
	// half-open (default 1).
	HalfOpenMaxRequests int
	// OnStateChange is called (outside the lock) after every transition.
	OnStateChange func(from, to State)
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Breaker is a consecutive-failure circuit breaker. It is safe for
// concurrent use.
type Breaker struct {
	cfg BreakerConfig

	mu         sync.Mutex
	state      State
	failures   int
	openedAt   time.Time
	probes     int
	generation uint64
}

// NewBreaker returns a closed breaker.
func NewBreaker(cfg BreakerConfig) (*Breaker, error) {
	if cfg.FailureThreshold < 1 {
		return nil, errors.New("failure threshold must be >= 1")
	}
	if cfg.OpenTimeout <= 0 {
		return nil, errors.New("open timeout must be positive")
	}
	if cfg.HalfOpenMaxRequests < 1 {
		cfg.HalfOpenMaxRequests = 1
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breaker{cfg: cfg}, nil
}

// State returns the current state, applying the open -> half-open timeout.
func (b *Breaker) State() State {
	b.mu.Lock()
	from, to := b.advanceLocked()
	s := b.state
	b.mu.Unlock()
	b.notify(from, to)
	return s
}

// Allow asks permission for a call. On success the caller must invoke
// done exactly once with the call's outcome.
func (b *Breaker) Allow() (done func(Outcome), err error) {
	b.mu.Lock()
	from, to := b.advanceLocked()
	switch b.state {
	case Open:
		b.mu.Unlock()
		b.notify(from, to)
		return nil, ErrOpen
	case HalfOpen:
		if b.probes >= b.cfg.HalfOpenMaxRequests {
			b.mu.Unlock()
			b.notify(from, to)
			return nil, ErrOpen
		}
		b.probes++
	}
	gen, admittedIn := b.generation, b.state
	b.mu.Unlock()
	b.notify(from, to)

	var once sync.Once
	return func(o Outcome) { once.Do(func() { b.record(gen, admittedIn, o) }) }, nil
}

func (b *Breaker) record(gen uint64, admittedIn State, o Outcome) {
	b.mu.Lock()
	if admittedIn == HalfOpen && gen == b.generation {
		b.probes--
	}
	// Results of calls admitted under an earlier state are stale.
	if gen != b.generation {
		b.mu.Unlock()
		return
	}
	from, to := b.state, b.state
	switch {
	case o == Ignore:
	case b.state == HalfOpen && o == Success:
		to = b.transitionLocked(Closed)
	case b.state == HalfOpen && o == Failure:
		to = b.transitionLocked(Open)
	case b.state == Closed && o == Success:
		b.failures = 0
	case b.state == Closed && o == Failure:
		b.failures++
		if b.failures >= b.cfg.FailureThreshold {
			to = b.transitionLocked(Open)
		}
	}
	b.mu.Unlock()
	b.notify(from, to)
}

// advanceLocked moves open -> half-open once the timeout elapsed.
func (b *Breaker) advanceLocked() (from, to State) {
	from = b.state
	if b.state == Open && b.cfg.Now().Sub(b.openedAt) >= b.cfg.OpenTimeout {
		return from, b.transitionLocked(HalfOpen)
	}
	return from, from
}

func (b *Breaker) transitionLocked(to State) State {
	b.state = to
	b.generation++
	b.failures = 0
	b.probes = 0
	if to == Open {
		b.openedAt = b.cfg.Now()
	}
	return to
}

func (b *Breaker) notify(from, to State) {
	if from != to && b.cfg.OnStateChange != nil {
		b.cfg.OnStateChange(from, to)
	}
}
