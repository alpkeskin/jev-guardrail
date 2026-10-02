package resilience

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestBreaker(t *testing.T, threshold, halfOpen int) (*Breaker, *fakeClock, *[]string) {
	t.Helper()
	clock := &fakeClock{now: time.Unix(0, 0)}
	var transitions []string
	var mu sync.Mutex
	b, err := NewBreaker(BreakerConfig{
		FailureThreshold: threshold, OpenTimeout: 10 * time.Second, HalfOpenMaxRequests: halfOpen, Now: clock.Now,
		OnStateChange: func(from, to State) {
			mu.Lock()
			transitions = append(transitions, from.String()+"->"+to.String())
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b, clock, &transitions
}

func call(t *testing.T, b *Breaker, o Outcome) error {
	t.Helper()
	done, err := b.Allow()
	if err != nil {
		return err
	}
	done(o)
	return nil
}

func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	b, _, tr := newTestBreaker(t, 3, 1)
	_ = call(t, b, Failure)
	_ = call(t, b, Failure)
	_ = call(t, b, Success) // resets the count
	_ = call(t, b, Failure)
	_ = call(t, b, Failure)
	if b.State() != Closed {
		t.Fatal("must stay closed: failures were not consecutive")
	}
	_ = call(t, b, Failure)
	if b.State() != Open {
		t.Fatalf("state = %s, want open", b.State())
	}
	if err := call(t, b, Success); !errors.Is(err, ErrOpen) {
		t.Fatalf("open breaker must reject, got %v", err)
	}
	if len(*tr) != 1 || (*tr)[0] != "closed->open" {
		t.Fatalf("transitions = %v", *tr)
	}
}

func TestBreakerIgnoreOutcome(t *testing.T) {
	b, _, _ := newTestBreaker(t, 2, 1)
	_ = call(t, b, Failure)
	_ = call(t, b, Ignore)
	_ = call(t, b, Ignore)
	_ = call(t, b, Failure)
	if b.State() != Open {
		t.Fatal("ignored outcomes must neither reset nor count")
	}
}

func TestBreakerHalfOpenRecovery(t *testing.T) {
	b, clock, tr := newTestBreaker(t, 1, 1)
	_ = call(t, b, Failure)
	clock.Advance(9 * time.Second)
	if b.State() != Open {
		t.Fatal("must stay open before timeout")
	}
	clock.Advance(time.Second)

	probe, err := b.Allow()
	if err != nil {
		t.Fatalf("probe rejected: %v", err)
	}
	if _, err := b.Allow(); !errors.Is(err, ErrOpen) {
		t.Fatal("only one probe may run while half-open")
	}
	probe(Success)
	if b.State() != Closed {
		t.Fatalf("state = %s, want closed", b.State())
	}
	want := []string{"closed->open", "open->half_open", "half_open->closed"}
	if len(*tr) != 3 || (*tr)[0] != want[0] || (*tr)[1] != want[1] || (*tr)[2] != want[2] {
		t.Fatalf("transitions = %v", *tr)
	}
}

func TestBreakerHalfOpenFailureReopens(t *testing.T) {
	b, clock, _ := newTestBreaker(t, 1, 1)
	_ = call(t, b, Failure)
	clock.Advance(10 * time.Second)
	_ = call(t, b, Failure)
	if b.State() != Open {
		t.Fatalf("state = %s, want open", b.State())
	}
	// The open timer restarted.
	clock.Advance(5 * time.Second)
	if b.State() != Open {
		t.Fatal("open timeout must restart after a failed probe")
	}
}

func TestBreakerIgnoredProbeFreesSlot(t *testing.T) {
	b, clock, _ := newTestBreaker(t, 1, 1)
	_ = call(t, b, Failure)
	clock.Advance(10 * time.Second)
	_ = call(t, b, Ignore)
	if b.State() != HalfOpen {
		t.Fatal("ignored probe must keep half-open")
	}
	if err := call(t, b, Success); err != nil {
		t.Fatalf("slot not freed: %v", err)
	}
	if b.State() != Closed {
		t.Fatal("successful probe must close")
	}
}

func TestBreakerStaleResultsIgnored(t *testing.T) {
	b, clock, _ := newTestBreaker(t, 1, 1)
	slow, _ := b.Allow() // admitted while closed
	_ = call(t, b, Failure)
	clock.Advance(10 * time.Second)
	probe, _ := b.Allow() // half-open probe
	slow(Failure)         // late result from the earlier generation
	if b.State() != HalfOpen {
		t.Fatalf("stale failure changed state to %s", b.State())
	}
	probe(Success)
	if b.State() != Closed {
		t.Fatal("probe success must close")
	}
}

func TestBreakerDoneIsIdempotent(t *testing.T) {
	b, _, _ := newTestBreaker(t, 2, 1)
	done, _ := b.Allow()
	done(Failure)
	done(Failure)
	if b.State() != Closed {
		t.Fatal("done must only count once")
	}
}

func TestBreakerConcurrent(t *testing.T) {
	b, clock, _ := newTestBreaker(t, 5, 3)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if done, err := b.Allow(); err == nil {
				done(Outcome(i % 3))
			}
			if i%50 == 0 {
				clock.Advance(10 * time.Second)
			}
		}(i)
	}
	wg.Wait()
	_ = b.State()
}

func TestNewBreakerValidation(t *testing.T) {
	if _, err := NewBreaker(BreakerConfig{FailureThreshold: 0, OpenTimeout: time.Second}); err == nil {
		t.Error("threshold 0 must fail")
	}
	if _, err := NewBreaker(BreakerConfig{FailureThreshold: 1}); err == nil {
		t.Error("zero open timeout must fail")
	}
}

func TestLimiter(t *testing.T) {
	l, err := NewLimiter(2, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	r1, _ := l.Acquire(context.Background())
	r2, _ := l.Acquire(context.Background())
	if l.InFlight() != 2 {
		t.Fatalf("in flight = %d", l.InFlight())
	}
	start := time.Now()
	if _, err := l.Acquire(context.Background()); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Fatal("must wait maxWait before rejecting")
	}
	r1()
	r1() // double release must not free a second slot
	if l.InFlight() != 1 {
		t.Fatalf("in flight = %d after double release", l.InFlight())
	}
	r3, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r2()
	r3()

	// A slot freed while waiting is picked up.
	ra, _ := l.Acquire(context.Background())
	rb, _ := l.Acquire(context.Background())
	go func() { time.Sleep(5 * time.Millisecond); ra() }()
	rc, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatalf("waiter not served: %v", err)
	}
	rb()
	rc()
}

func TestLimiterContextCanceled(t *testing.T) {
	l, _ := NewLimiter(1, time.Second)
	r, _ := l.Acquire(context.Background())
	defer r()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestLimiterNoWait(t *testing.T) {
	l, _ := NewLimiter(1, 0)
	r, _ := l.Acquire(context.Background())
	defer r()
	if _, err := l.Acquire(context.Background()); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v", err)
	}
	if _, err := NewLimiter(0, 0); err == nil {
		t.Fatal("limit 0 must fail")
	}
}
