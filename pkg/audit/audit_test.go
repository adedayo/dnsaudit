package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// stub builds a check that records its invocation and returns a fixed outcome.
func stub(name string, network Network, out Outcome, err error) Check {
	return CheckFunc{
		Description: Description{
			Name:           name,
			Summary:        name + " stub",
			Network:        []Network{network},
			TypicalQueries: 1,
		},
		Fn: func(context.Context, Target) (Outcome, error) { return out, err },
	}
}

// withRegistry swaps in a clean registry for the duration of a test, so that
// registry assertions never depend on what the production init() happens to
// have registered.
func withRegistry(t *testing.T, checks ...Check) {
	t.Helper()
	registryMu.Lock()
	saved := registry
	registry = map[string]Check{}
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})
	for _, c := range checks {
		Register(c)
	}
}

func TestProductionRegistryIsValid(t *testing.T) {
	// The real registry must be self-consistent: every declared finding ID has
	// to exist in the catalogue, or the tool would promise detail it cannot
	// deliver.
	require.NoError(t, ValidateRegistry())
	assert.NotEmpty(t, Names())
}

func TestEveryProfileMemberIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, n := range Names() {
		registered[n] = true
	}
	for profile, members := range profileMembers {
		for _, m := range members {
			assert.Truef(t, registered[m],
				"profile %q names unregistered check %q", profile, m)
		}
		if members != nil {
			assert.NotEmptyf(t, profileSummaries[profile],
				"profile %q has no summary", profile)
		}
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	withRegistry(t, stub("a", NetworkDNS, Outcome{}, nil))
	assert.Panics(t, func() { Register(stub("a", NetworkDNS, Outcome{}, nil)) })
}

func TestLookupAndNames(t *testing.T) {
	withRegistry(t,
		stub("zulu", NetworkDNS, Outcome{}, nil),
		stub("alpha", NetworkDNS, Outcome{}, nil),
	)
	// Names must be sorted so that output is reproducible run to run, which is
	// a prerequisite for the drift detection planned in spec 013.
	assert.Equal(t, []string{"alpha", "zulu"}, Names())

	c, ok := Lookup("alpha")
	require.True(t, ok)
	assert.Equal(t, "alpha", c.Describe().Name)

	_, ok = Lookup("missing")
	assert.False(t, ok)
}

func TestDescriptionRequiresNetwork(t *testing.T) {
	assert.False(t, Description{Network: []Network{NetworkDNS}}.RequiresNetwork())
	assert.False(t, Description{Network: []Network{NetworkNone}}.RequiresNetwork())
	assert.True(t, Description{Network: []Network{NetworkDNS, NetworkHTTPS}}.RequiresNetwork())
	assert.True(t, Description{Network: []Network{NetworkThirdParty}}.RequiresNetwork())
}

func TestDescriptionExcludedByNoNetwork(t *testing.T) {
	// Using egress is not the same as depending on it. A check that still
	// detects a missing control from DNS alone must survive --no-network,
	// otherwise the run reports silence as safety.
	assert.False(t, Description{Network: []Network{NetworkDNS}}.ExcludedByNoNetwork())
	assert.True(t, Description{Network: []Network{NetworkDNS, NetworkHTTPS}}.ExcludedByNoNetwork())
	assert.False(t, Description{
		Network:                []Network{NetworkDNS, NetworkHTTPS},
		DegradesWithoutNetwork: true,
	}.ExcludedByNoNetwork())
}

// TestMTASTSSurvivesNoNetwork pins the real registered check, not a stub. The
// bug this guards against was that --no-network removed MTA-STS entirely, so a
// domain publishing no policy at all was reported clean.
func TestMTASTSSurvivesNoNetwork(t *testing.T) {
	desc := mtastsCheck().Describe()
	assert.True(t, desc.RequiresNetwork(), "the policy fetch is HTTPS egress and must be declared")
	assert.False(t, desc.ExcludedByNoNetwork(), "MTA-STS must still run DNS-only under --no-network")
}

func TestParseProfile(t *testing.T) {
	for _, name := range Profiles() {
		p, err := ParseProfile(name)
		require.NoErrorf(t, err, "profile %q should parse", name)
		assert.NotEmpty(t, p.Summary())
	}

	p, err := ParseProfile("  QUICK ")
	require.NoError(t, err)
	assert.Equal(t, ProfileQuick, p)

	_, err = ParseProfile("nonsense")
	require.Error(t, err)
	// The message must list the alternatives; an agent recovering from a bad
	// argument should not have to guess.
	assert.Contains(t, err.Error(), "quick")
}

func TestSelectionResolve(t *testing.T) {
	withRegistry(t,
		stub("spf", NetworkDNS, Outcome{}, nil),
		stub("dmarc", NetworkDNS, Outcome{}, nil),
		stub("mtasts", NetworkHTTPS, Outcome{}, nil),
	)

	names := func(cs []Check) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Describe().Name)
		}
		return out
	}

	t.Run("defaults to standard", func(t *testing.T) {
		cs, err := Selection{}.Resolve()
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"spf", "dmarc", "mtasts"}, names(cs))
	})

	t.Run("only replaces the profile", func(t *testing.T) {
		cs, err := Selection{Profile: ProfileQuick, Only: []string{"mtasts"}}.Resolve()
		require.NoError(t, err)
		assert.Equal(t, []string{"mtasts"}, names(cs))
	})

	t.Run("skip is applied last", func(t *testing.T) {
		cs, err := Selection{Only: []string{"spf", "dmarc"}, Skip: []string{"spf"}}.Resolve()
		require.NoError(t, err)
		assert.Equal(t, []string{"dmarc"}, names(cs))
	})

	t.Run("no-network drops egress checks", func(t *testing.T) {
		cs, err := Selection{NoNetwork: true}.Resolve()
		require.NoError(t, err)
		assert.NotContains(t, names(cs), "mtasts")
	})

	t.Run("unknown names are rejected", func(t *testing.T) {
		_, err := Selection{Only: []string{"typo"}}.Resolve()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "typo")

		_, err = Selection{Skip: []string{"typo"}}.Resolve()
		require.Error(t, err)
	})

	t.Run("empty selection is an error", func(t *testing.T) {
		_, err := Selection{Only: []string{"spf"}, Skip: []string{"spf"}}.Resolve()
		require.Error(t, err)
	})
}

func TestRunnerMergesDeterministically(t *testing.T) {
	withRegistry(t)
	check := CheckFunc{
		Description: Description{Name: "stub", Network: []Network{NetworkDNS}},
		Fn: func(_ context.Context, tg Target) (Outcome, error) {
			return Outcome{State: finding.StateOK, Records: []string{"r:" + tg.Domain}}, nil
		},
	}

	targets := []string{"c.example", "a.example", "b.example"}
	var first []finding.CheckResult
	for i := 0; i < 5; i++ {
		r := &Runner{Checks: []Check{check}, Concurrency: 4}
		res := finding.NewResult("dnsaudit", "test")
		require.NoError(t, r.Run(context.Background(), res, targets...))
		res.Finalise()
		if i == 0 {
			first = res.Checks
			continue
		}
		// Concurrency must not leak into the output: identical inputs have to
		// produce byte-identical results, otherwise baselining is impossible.
		assert.Equal(t, first, res.Checks)
	}
	require.Len(t, first, 3)
	assert.Equal(t, []string{"a.example", "b.example", "c.example"},
		[]string{first[0].Target, first[1].Target, first[2].Target})
}

func TestRunnerIsolatesCheckFailures(t *testing.T) {
	withRegistry(t)
	good := stub("good", NetworkDNS, Outcome{State: finding.StateOK, Records: []string{"ok"}}, nil)
	bad := stub("bad", NetworkDNS, Outcome{}, errors.New("i/o timeout"))

	r := &Runner{Checks: []Check{good, bad}, CheckConcurrency: 2}
	res := finding.NewResult("dnsaudit", "test")
	require.NoError(t, r.Run(context.Background(), res, "example.com"))
	res.Finalise()

	// One failing check must never suppress the others: a partial answer that
	// says what is missing beats no answer at all.
	require.Len(t, res.Errors, 1)
	assert.Equal(t, "bad", res.Errors[0].Check)
	assert.Equal(t, finding.ErrCodeTimeout, res.Errors[0].Code)
	assert.True(t, res.Errors[0].Retryable)

	states := map[string]finding.State{}
	for _, c := range res.Checks {
		states[c.Check] = c.State
	}
	assert.Equal(t, finding.StateOK, states["good"])
	assert.Equal(t, finding.StateCheckFailed, states["bad"])
}

func TestRunnerRejectsEmptyInput(t *testing.T) {
	res := finding.NewResult("dnsaudit", "test")
	require.Error(t, (&Runner{}).Run(context.Background(), res, "example.com"))

	check := stub("stub", NetworkDNS, Outcome{}, nil)
	require.Error(t, (&Runner{Checks: []Check{check}}).Run(context.Background(), res))
	require.Error(t, (&Runner{Checks: []Check{check}}).Run(context.Background(), res, "  "))
}

func TestRunnerReportsProgress(t *testing.T) {
	var (
		mu    sync.Mutex
		seen  int
		total int
	)
	r := &Runner{
		Checks:      []Check{stub("stub", NetworkDNS, Outcome{State: finding.StateOK}, nil)},
		Concurrency: 3,
		Progress: func(_ string, _, t int) {
			mu.Lock()
			defer mu.Unlock()
			seen++
			total = t
		},
	}
	res := finding.NewResult("dnsaudit", "test")
	require.NoError(t, r.Run(context.Background(), res, "a.example", "b.example", "c.example"))
	assert.Equal(t, 3, seen)
	assert.Equal(t, 3, total)
}

func TestNormaliseTargets(t *testing.T) {
	got := normaliseTargets([]string{"  Example.COM ", "example.com", "", "b.example.", "  "})
	// De-duplication has to be case- and trailing-dot-insensitive, or a bulk
	// input file would be billed twice for the same domain.
	assert.Equal(t, []string{"example.com", "b.example"}, got)
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		msg       string
		code      finding.ErrorCode
		retryable bool
	}{
		{"context deadline exceeded", finding.ErrCodeTimeout, true},
		{"read udp: i/o timeout", finding.ErrCodeTimeout, true},
		{"dns query failed", finding.ErrCodeResolverUnreachable, true},
		{"no resolvers configured", finding.ErrCodeResolverUnreachable, true},
		{"record not found", finding.ErrCodeNotFound, false},
		{"malformed record", finding.ErrCodeInvalidRecord, false},
		{"something unexpected", finding.ErrCodeInternal, false},
	}
	for _, c := range cases {
		t.Run(c.msg, func(t *testing.T) {
			got := ClassifyError("spf", "example.com", errors.New(c.msg))
			assert.Equal(t, c.code, got.Code)
			assert.Equal(t, c.retryable, got.Retryable)
			assert.Equal(t, "spf", got.Check)
			assert.Equal(t, "example.com", got.Target)
			if c.retryable {
				assert.Positive(t, got.RetryAfterSeconds,
					"a retryable error must tell the caller how long to wait")
			}
		})
	}
}

func TestGrade(t *testing.T) {
	assert.Equal(t, "A", Grade(finding.Summary{}))
	assert.Equal(t, "A", Grade(finding.Summary{Info: 9, Total: 9}))
	assert.Equal(t, "B", Grade(finding.Summary{Low: 1, Total: 1}))
	assert.Equal(t, "B", Grade(finding.Summary{Medium: 1, Total: 1}))
	assert.Equal(t, "C", Grade(finding.Summary{Medium: 3, Total: 3}))
	assert.Equal(t, "D", Grade(finding.Summary{High: 1, Total: 1}))
	assert.Equal(t, "E", Grade(finding.Summary{High: 3, Total: 3}))
	// A single critical outranks everything: one exploitable weakness is
	// enough to fail the whole domain.
	assert.Equal(t, "F", Grade(finding.Summary{Critical: 1, High: 1, Total: 2}))

	for _, g := range []string{"A", "B", "C", "D", "E", "F"} {
		assert.NotEmptyf(t, GradeDescription(g), "grade %s needs a description", g)
	}
}

func TestCacheDeduplicatesConcurrentQueries(t *testing.T) {
	c := NewCache()

	// Prime the cache through the public surface would require a resolver, so
	// exercise de-duplication directly: many goroutines asking the identical
	// question must collapse to one lookup.
	const goroutines = 32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = c.LookupTXT(context.Background(), "invalid.")
		}()
	}
	wg.Wait()

	hits, misses := c.Stats()
	assert.Equal(t, 1, misses, "the same question must only be asked once")
	assert.Equal(t, goroutines-1, hits)
}

func TestCacheSeparatesQuestions(t *testing.T) {
	c := NewCache()
	for i := 0; i < 3; i++ {
		_, _, _ = c.LookupTXT(context.Background(), fmt.Sprintf("q%d.invalid.", i))
	}
	hits, misses := c.Stats()
	assert.Equal(t, 3, misses)
	assert.Zero(t, hits)
}

// TestCacheJoinsSplitTXTStrings guards a false-positive source. A TXT record
// over 255 bytes travels as several strings; treating them as separate records
// splits a 2048-bit DKIM key into unparseable fragments and makes one long SPF
// record look like the duplicate that RFC 7208 says is a PermError.
func TestCacheJoinsSplitTXTStrings(t *testing.T) {
	tests := map[string]struct {
		strings []string
		want    string
	}{
		"single string is unchanged": {
			strings: []string{"v=spf1 -all"},
			want:    "v=spf1 -all",
		},
		"split record is rejoined verbatim": {
			strings: []string{"v=spf1 ip4:192.0.2.0/24 ", "include:example.net ", "-all"},
			want:    "v=spf1 ip4:192.0.2.0/24 include:example.net -all",
		},
		"no separator is introduced": {
			strings: []string{"v=DKIM1; k=rsa; p=AAAA", "BBBB", "CCCC"},
			want:    "v=DKIM1; k=rsa; p=AAAABBBBCCCC",
		},
		"empty record": {strings: nil, want: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, joinTXT(&dns.TXT{Txt: tc.strings}))
		})
	}
}

func TestRunnerString(t *testing.T) {
	r := &Runner{Checks: []Check{stub("b", NetworkDNS, Outcome{}, nil), stub("a", NetworkDNS, Outcome{}, nil)}}
	assert.Equal(t, []string{"a", "b"}, r.SortedCheckNames())
	assert.Contains(t, r.String(), "a")
}
