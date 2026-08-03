package vantage

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetTimeouts restores the default timeout configuration after a test.
func resetTimeouts(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		SetQueryTimeout(0)
		SetTotalTimeout(0)
	})
}

func TestTimeoutDefaults(t *testing.T) {
	resetTimeouts(t)
	assert.Equal(t, DefaultQueryTimeout, QueryTimeout())
	assert.Equal(t, DefaultTotalTimeout, TotalTimeout())
	assert.Less(t, DefaultQueryTimeout, DefaultTotalTimeout,
		"a single attempt must be shorter than the overall budget for failover to work")
}

func TestTimeoutSettersOverrideDefaults(t *testing.T) {
	resetTimeouts(t)

	SetQueryTimeout(250 * time.Millisecond)
	SetTotalTimeout(3 * time.Second)
	assert.Equal(t, 250*time.Millisecond, QueryTimeout())
	assert.Equal(t, 3*time.Second, TotalTimeout())

	// A non-positive value restores the default.
	SetQueryTimeout(0)
	SetTotalTimeout(-1)
	assert.Equal(t, DefaultQueryTimeout, QueryTimeout())
	assert.Equal(t, DefaultTotalTimeout, TotalTimeout())
}

func TestTimeoutsFromEnvironment(t *testing.T) {
	resetTimeouts(t)

	t.Setenv(QueryTimeoutEnvVar, "750ms")
	t.Setenv(TotalTimeoutEnvVar, "20s")
	assert.Equal(t, 750*time.Millisecond, QueryTimeout())
	assert.Equal(t, 20*time.Second, TotalTimeout())

	// Setters take precedence over the environment.
	SetQueryTimeout(100 * time.Millisecond)
	assert.Equal(t, 100*time.Millisecond, QueryTimeout())
}

func TestInvalidEnvironmentTimeoutsFallBackToDefaults(t *testing.T) {
	resetTimeouts(t)

	t.Setenv(QueryTimeoutEnvVar, "not-a-duration")
	t.Setenv(TotalTimeoutEnvVar, "-5s")
	assert.Equal(t, DefaultQueryTimeout, QueryTimeout())
	assert.Equal(t, DefaultTotalTimeout, TotalTimeout())
}

func TestAttemptTimeoutIsCappedByRemainingBudget(t *testing.T) {
	resetTimeouts(t)
	SetQueryTimeout(2 * time.Second)

	assert.Equal(t, 2*time.Second, attemptTimeout(5*time.Second),
		"plenty of budget left: use the full query timeout")
	assert.Equal(t, 300*time.Millisecond, attemptTimeout(300*time.Millisecond),
		"little budget left: never overrun the overall deadline")
}

func TestBudgetHonoursTheSoonerOfContextAndTotalTimeout(t *testing.T) {
	resetTimeouts(t)
	SetTotalTimeout(10 * time.Second)

	remaining, err := budget(context.Background())
	require.NoError(t, err)
	assert.InDelta(t, float64(10*time.Second), float64(remaining), float64(time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	remaining, err = budget(ctx)
	require.NoError(t, err)
	assert.LessOrEqual(t, remaining, time.Second)

	expired, cancelExpired := context.WithTimeout(context.Background(), -time.Second)
	defer cancelExpired()
	_, err = budget(expired)
	assert.EqualError(t, err, "error: context deadline exceeded")
}

// TestFastFailoverToWorkingResolver is the behavioural guarantee: a blackholed
// resolver must be abandoned after the (short) query timeout so the next
// resolver still answers well inside the overall budget.
func TestFastFailoverToWorkingResolver(t *testing.T) {
	resetTimeouts(t)
	SetQueryTimeout(200 * time.Millisecond)
	SetTotalTimeout(5 * time.Second)

	mux := dns.NewServeMux()
	mux.HandleFunc("failover.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "failover.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"v=spf1 -all"},
		})
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	// 192.0.2.0/24 (TEST-NET-1) is guaranteed unroutable.
	SetResolvers("192.0.2.1", "192.0.2.2", addr)
	t.Cleanup(func() {
		SetResolvers()
		ResetResolverCache()
	})

	start := time.Now()
	txts, err := LookupTXT(context.Background(), "failover.test")
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, []string{"v=spf1 -all"}, txts)
	assert.Less(t, elapsed, 2*time.Second,
		"two dead resolvers should be skipped quickly, not stall the lookup")
}

// TestTotalTimeoutBoundsFailover ensures the overall budget is respected even
// when every resolver is unreachable.
func TestTotalTimeoutBoundsFailover(t *testing.T) {
	resetTimeouts(t)
	SetQueryTimeout(200 * time.Millisecond)
	SetTotalTimeout(600 * time.Millisecond)

	SetResolvers("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5")
	t.Cleanup(func() {
		SetResolvers()
		ResetResolverCache()
	})

	start := time.Now()
	_, err := LookupTXT(context.Background(), "unreachable.test")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error: dns query failed")
	assert.Less(t, elapsed, 2*time.Second, "the total timeout must bound the whole lookup")
}
