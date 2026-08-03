package dnsaudit

import (
	"context"
	"sync"
	"time"
)

// DefaultQueryRate is the maximum queries per second issued to any single
// resolver.
//
// The limit exists for two reasons. A burst of concurrent queries can trip
// rate limiting or DDoS protection, in which case the tool starts receiving
// timeouts and refusals and reports them as security findings — wrong answers
// are worse than slow ones. And the tool queries infrastructure that belongs to
// someone else, so it should never be mistaken for an attack.
const DefaultQueryRate = 50

// QueryRateEnvVar overrides the default rate.
const QueryRateEnvVar = "DNSAUDIT_QUERY_RATE"

var (
	rateMu      sync.Mutex
	queryRate   = DefaultQueryRate
	limiters    = map[string]*limiter{}
	rateEnabled = true
)

// SetQueryRate sets the per-resolver queries-per-second limit. A rate of zero
// or less disables limiting.
func SetQueryRate(perSecond int) {
	rateMu.Lock()
	defer rateMu.Unlock()
	queryRate = perSecond
	rateEnabled = perSecond > 0
	// Discard existing limiters so the new rate takes effect immediately.
	limiters = map[string]*limiter{}
}

// QueryRate returns the configured per-resolver rate limit.
func QueryRate() int {
	rateMu.Lock()
	defer rateMu.Unlock()
	return queryRate
}

// limiter is a minimal token bucket. A dependency-free implementation keeps the
// module's supply chain small, which matters for a security tool.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// wait blocks until the next query to this resolver is permitted, or until the
// context is done. It never blocks longer than the caller's deadline allows.
func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	delay := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// awaitQuerySlot applies the rate limit for a resolver.
func awaitQuerySlot(ctx context.Context, server string) error {
	rateMu.Lock()
	if !rateEnabled {
		rateMu.Unlock()
		return nil
	}
	l, ok := limiters[server]
	if !ok {
		l = &limiter{interval: time.Second / time.Duration(queryRate)}
		limiters[server] = l
	}
	rateMu.Unlock()

	return l.wait(ctx)
}

// ResetQueryRate restores the default rate. It exists for tests.
func ResetQueryRate() {
	SetQueryRate(DefaultQueryRate)
}
