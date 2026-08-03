package analyse

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResolver serves records from a map, so the evaluation logic can be tested
// exhaustively — including the adversarial cases — without a resolver.
type fakeResolver struct {
	txt map[string][]string
	// hosts names the domains that have A/MX records. Anything absent is a
	// void lookup.
	hosts map[string]bool
	// queries counts lookups, to assert that evaluation stays bounded.
	queries int
}

func (f *fakeResolver) TXT(_ context.Context, name string) ([]string, error) {
	f.queries++
	records, ok := f.txt[normaliseDomain(name)]
	if !ok {
		return nil, fmt.Errorf("error: not found")
	}
	return records, nil
}

func (f *fakeResolver) HasRecords(_ context.Context, name, _ string) (bool, error) {
	f.queries++
	return f.hosts[normaliseDomain(name)], nil
}

// chain builds a resolver whose includes form a linear chain of the given
// length, each link costing exactly one lookup.
func chain(length int) (*fakeResolver, string) {
	f := &fakeResolver{txt: map[string][]string{}, hosts: map[string]bool{}}
	for i := 1; i <= length; i++ {
		record := "v=spf1 ip4:192.0.2." + fmt.Sprint(i) + " -all"
		if i < length {
			record = fmt.Sprintf("v=spf1 include:link%d.example -all", i+1)
		}
		f.txt[fmt.Sprintf("link%d.example", i)] = []string{record}
	}
	return f, "v=spf1 include:link1.example -all"
}

func TestEvaluateSPFCountsLookups(t *testing.T) {
	tests := map[string]struct {
		record string
		want   int
	}{
		"ip4 costs nothing":      {record: "v=spf1 ip4:192.0.2.0/24 -all", want: 0},
		"a costs one":            {record: "v=spf1 a -all", want: 1},
		"mx costs one":           {record: "v=spf1 mx -all", want: 1},
		"exists costs one":       {record: "v=spf1 exists:%{i}.example -all", want: 1},
		"ptr costs one":          {record: "v=spf1 ptr -all", want: 1},
		"qualifiers are ignored": {record: "v=spf1 -a ~mx ?ip4:192.0.2.1 -all", want: 2},
		"all together":           {record: "v=spf1 a mx ip4:192.0.2.1 ip6:2001:db8::/64 -all", want: 2},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := &fakeResolver{
				txt:   map[string][]string{},
				hosts: map[string]bool{"example.com": true},
			}
			got := EvaluateSPF(context.Background(), f, "example.com", tc.record)
			assert.Equal(t, tc.want, got.Lookups)
		})
	}
}

// TestEvaluateSPFAtAndOverTheLimit is the case spec 011 exists for: ten lookups
// is compliant, eleven fails open at receivers, and nothing about the record
// itself reveals the difference.
func TestEvaluateSPFAtAndOverTheLimit(t *testing.T) {
	t.Run("exactly ten is compliant", func(t *testing.T) {
		f, record := chain(10)
		eval := EvaluateSPF(context.Background(), f, "example.com", record)
		assert.Equal(t, 10, eval.Lookups)

		got := ids(SPFRecursive(context.Background(), Origin{Target: "example.com"},
			f, []string{record}, true))
		assert.NotContains(t, got, "SURF-SPF-006")
	})

	t.Run("eleven exceeds the limit", func(t *testing.T) {
		f, record := chain(11)
		eval := EvaluateSPF(context.Background(), f, "example.com", record)
		assert.Equal(t, 11, eval.Lookups)

		findings := SPFRecursive(context.Background(), Origin{Target: "example.com"},
			f, []string{record}, true)
		assert.Contains(t, ids(findings), "SURF-SPF-006")

		// The computed count must be evidence: an operator has to know how far
		// over the limit they are to know how much to cut.
		var sawCount bool
		for _, fnd := range findings {
			for _, e := range fnd.Evidence {
				if e.Name == "spf.lookup_count" && e.Value == "11" {
					sawCount = true
				}
			}
		}
		assert.True(t, sawCount, "the computed lookup count must be reported as evidence")
	})
}

// TestEvaluateSPFIncludeLoopTerminates is the adversarial case: a record that
// includes itself must produce a finding, not a hang.
func TestEvaluateSPFIncludeLoopTerminates(t *testing.T) {
	f := &fakeResolver{
		txt: map[string][]string{
			"a.example": {"v=spf1 include:b.example -all"},
			"b.example": {"v=spf1 include:a.example -all"},
		},
		hosts: map[string]bool{},
	}

	eval := EvaluateSPF(context.Background(), f, "a.example", "v=spf1 include:b.example -all")
	require.True(t, eval.Loop, "the cycle must be detected")
	assert.Equal(t, "a.example", eval.LoopAt, "the finding must name the offending domain")
	assert.Less(t, f.queries, 10, "a cycle must not be walked repeatedly")

	got := ids(SPFRecursive(context.Background(), Origin{Target: "a.example"},
		f, []string{"v=spf1 include:b.example -all"}, true))
	assert.Contains(t, got, "SURF-SPF-009")
}

// TestEvaluateSPFSelfInclude covers the direct case of the same defect.
func TestEvaluateSPFSelfInclude(t *testing.T) {
	f := &fakeResolver{txt: map[string][]string{}, hosts: map[string]bool{}}
	eval := EvaluateSPF(context.Background(), f, "example.com", "v=spf1 include:example.com -all")
	assert.True(t, eval.Loop)
}

func TestEvaluateSPFVoidLookups(t *testing.T) {
	f := &fakeResolver{
		txt:   map[string][]string{},
		hosts: map[string]bool{}, // nothing resolves
	}
	record := "v=spf1 a:one.example a:two.example a:three.example -all"

	eval := EvaluateSPF(context.Background(), f, "example.com", record)
	assert.Equal(t, 3, eval.VoidLookups)
	assert.Len(t, eval.VoidNames, 3)

	got := ids(SPFRecursive(context.Background(), Origin{Target: "example.com"},
		f, []string{record}, true))
	assert.Contains(t, got, "SURF-SPF-007")
}

func TestEvaluateSPFVoidLimitIsTwo(t *testing.T) {
	f := &fakeResolver{txt: map[string][]string{}, hosts: map[string]bool{}}
	record := "v=spf1 a:one.example a:two.example -all"

	got := ids(SPFRecursive(context.Background(), Origin{Target: "example.com"},
		f, []string{record}, true))
	assert.NotContains(t, got, "SURF-SPF-007", "two void lookups are permitted")
}

func TestEvaluateSPFBrokenIncludes(t *testing.T) {
	f := &fakeResolver{
		txt: map[string][]string{
			// Resolves, but publishes no SPF record: still a PermError for the
			// including domain, and easy to miss by eye.
			"nospf.example": {"some-other-txt-record"},
		},
		hosts: map[string]bool{},
	}
	record := "v=spf1 include:nospf.example include:missing.example -all"

	eval := EvaluateSPF(context.Background(), f, "example.com", record)
	assert.Len(t, eval.BrokenTerms, 2)

	got := ids(SPFRecursive(context.Background(), Origin{Target: "example.com"},
		f, []string{record}, true))
	assert.Contains(t, got, "SURF-SPF-009")
}

// TestEvaluateSPFMacrosAreNotProbed guards against manufacturing a void lookup:
// a macro target cannot be resolved without a message to expand it against, so
// probing it would invent evidence a receiver would never see.
func TestEvaluateSPFMacrosAreNotProbed(t *testing.T) {
	f := &fakeResolver{txt: map[string][]string{}, hosts: map[string]bool{}}

	eval := EvaluateSPF(context.Background(), f,
		"example.com", "v=spf1 exists:%{ir}.spf.example -all")
	assert.Equal(t, 1, eval.Lookups, "the mechanism still costs a lookup")
	assert.Zero(t, eval.VoidLookups, "a macro target must not be counted as void")
}

// TestEvaluateSPFIsBounded ensures a pathological record cannot turn the tool
// into a query amplifier against someone else's nameservers.
func TestEvaluateSPFIsBounded(t *testing.T) {
	f, record := chain(200)
	eval := EvaluateSPF(context.Background(), f, "example.com", record)

	assert.True(t, eval.Bounded)
	assert.LessOrEqual(t, eval.Lookups, spfMaxLookups)
}

func TestEvaluateSPFHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f, record := chain(20)
	eval := EvaluateSPF(ctx, f, "example.com", record)
	assert.True(t, eval.Bounded)
	assert.Zero(t, f.queries, "a cancelled context must stop before querying")
}

func TestSPFRecursiveLength(t *testing.T) {
	f := &fakeResolver{txt: map[string][]string{}, hosts: map[string]bool{}}
	long := "v=spf1 " + strings.Repeat("ip4:192.0.2.1 ", 40) + "-all"
	require.Greater(t, len(long), 512)

	got := ids(SPFRecursive(context.Background(), Origin{Target: "example.com"},
		f, []string{long}, true))
	assert.Contains(t, got, "SURF-SPF-010")
}

// TestSPFRecursiveWithoutResolverStillAppliesRecordRules keeps the two entry
// points consistent: the caller without a resolver loses depth, not the basics.
func TestSPFRecursiveWithoutResolverStillAppliesRecordRules(t *testing.T) {
	got := ids(SPFRecursive(context.Background(), Origin{Target: "example.com"},
		nil, []string{"v=spf1 +all"}, true))
	assert.Equal(t, []string{"SURF-SPF-004"}, got)
}

func TestSPFRecursiveCleanRecordIsClean(t *testing.T) {
	f := &fakeResolver{
		txt:   map[string][]string{"_spf.example": {"v=spf1 ip4:192.0.2.0/24 -all"}},
		hosts: map[string]bool{"example.com": true},
	}
	got := SPFRecursive(context.Background(), Origin{Target: "example.com"},
		f, []string{"v=spf1 mx include:_spf.example -all"}, true)
	assert.Empty(t, got)
}
