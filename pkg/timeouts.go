package vantage

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// Timeout defaults.
//
// Two independent budgets are applied to every lookup:
//
//   - The *query* timeout bounds a single attempt against a single resolver.
//     Keeping it short means an unreachable nameserver is abandoned quickly and
//     the next one is tried, rather than stalling the whole audit.
//   - The *total* timeout bounds the lookup as a whole, across all resolvers.
//
// The defaults favour fast failover. Users auditing over slow, lossy or
// high-latency links (satellite, VPN, Tor, heavily filtered networks) can raise
// either budget via the CLI flags, the environment, or the library setters.
const (
	// DefaultQueryTimeout bounds a single attempt against a single resolver.
	DefaultQueryTimeout = 2 * time.Second
	// DefaultTotalTimeout bounds the entire lookup across all resolvers.
	DefaultTotalTimeout = 10 * time.Second
)

// DefaultTimeout is retained for backwards compatibility.
//
// Deprecated: use DefaultTotalTimeout (overall budget) or DefaultQueryTimeout
// (per-resolver budget) instead.
const DefaultTimeout = DefaultTotalTimeout

// Environment variables for tuning the timeouts without code or flags. Both
// accept any Go duration string, e.g. "500ms", "3s", "1m".
const (
	QueryTimeoutEnvVar = "VANTAGE_QUERY_TIMEOUT"
	TotalTimeoutEnvVar = "VANTAGE_TIMEOUT"
)

var (
	timeoutMu    sync.RWMutex
	queryTimeout time.Duration
	totalTimeout time.Duration
)

// SetQueryTimeout sets the per-resolver attempt timeout. A non-positive value
// restores the default. Lower it for snappier failover; raise it for slow links.
func SetQueryTimeout(d time.Duration) {
	timeoutMu.Lock()
	defer timeoutMu.Unlock()
	queryTimeout = d
}

// SetTotalTimeout sets the overall per-lookup timeout spanning all resolvers.
// A non-positive value restores the default.
func SetTotalTimeout(d time.Duration) {
	timeoutMu.Lock()
	defer timeoutMu.Unlock()
	totalTimeout = d
}

// QueryTimeout returns the effective per-resolver attempt timeout: the value set
// via SetQueryTimeout, else VANTAGE_QUERY_TIMEOUT, else DefaultQueryTimeout.
func QueryTimeout() time.Duration {
	timeoutMu.RLock()
	d := queryTimeout
	timeoutMu.RUnlock()
	if d > 0 {
		return d
	}
	if d, ok := durationFromEnv(QueryTimeoutEnvVar); ok {
		return d
	}
	return DefaultQueryTimeout
}

// TotalTimeout returns the effective overall lookup timeout: the value set via
// SetTotalTimeout, else VANTAGE_TIMEOUT, else DefaultTotalTimeout.
func TotalTimeout() time.Duration {
	timeoutMu.RLock()
	d := totalTimeout
	timeoutMu.RUnlock()
	if d > 0 {
		return d
	}
	if d, ok := durationFromEnv(TotalTimeoutEnvVar); ok {
		return d
	}
	return DefaultTotalTimeout
}

// durationFromEnv parses a positive duration from an environment variable.
func durationFromEnv(name string) (time.Duration, bool) {
	raw := os.Getenv(name)
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

// budget returns the time remaining for the whole lookup: the smaller of the
// configured total timeout and the caller's context deadline.
func budget(ctx context.Context) (time.Duration, error) {
	remaining := TotalTimeout()
	if deadline, ok := ctx.Deadline(); ok {
		if untilDeadline := time.Until(deadline); untilDeadline < remaining {
			remaining = untilDeadline
		}
	}
	if remaining <= 0 {
		return 0, fmt.Errorf("error: context deadline exceeded")
	}
	return remaining, nil
}

// attemptTimeout returns the timeout for a single resolver attempt: the
// per-query timeout, capped by whatever remains of the overall budget.
func attemptTimeout(remaining time.Duration) time.Duration {
	if q := QueryTimeout(); q < remaining {
		return q
	}
	return remaining
}
