package resilience

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrLimitExceeded is returned when no slot became free in time.
var ErrLimitExceeded = errors.New("concurrency limit exceeded")

// Limiter bounds the number of concurrent calls. Callers wait at most
// maxWait for a slot, so a slow dependency cannot pile up unbounded
// goroutines and connections.
type Limiter struct {
	slots   chan struct{}
	maxWait time.Duration
}

// NewLimiter returns a limiter with max concurrent slots.
func NewLimiter(max int, maxWait time.Duration) (*Limiter, error) {
	if max < 1 {
		return nil, errors.New("concurrency limit must be >= 1")
	}
	if maxWait < 0 {
		return nil, errors.New("max wait must not be negative")
	}
	return &Limiter{slots: make(chan struct{}, max), maxWait: maxWait}, nil
}

// Acquire waits for a slot. The returned release func must be called
// exactly once. It returns ErrLimitExceeded after maxWait, or ctx.Err().
func (l *Limiter) Acquire(ctx context.Context) (release func(), err error) {
	select {
	case l.slots <- struct{}{}:
		return l.releaseFunc(), nil
	default:
	}
	if l.maxWait == 0 {
		return nil, ErrLimitExceeded
	}
	t := time.NewTimer(l.maxWait)
	defer t.Stop()
	select {
	case l.slots <- struct{}{}:
		return l.releaseFunc(), nil
	case <-t.C:
		return nil, ErrLimitExceeded
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *Limiter) releaseFunc() func() {
	var once sync.Once
	return func() { once.Do(func() { <-l.slots }) }
}

// InFlight returns the number of held slots.
func (l *Limiter) InFlight() int { return len(l.slots) }

// Capacity returns the maximum number of slots.
func (l *Limiter) Capacity() int { return cap(l.slots) }
