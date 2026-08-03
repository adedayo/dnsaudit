package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFinaliseSortsBySeverityThenTargetThenCheck(t *testing.T) {
	r := NewResult("vantage", "test")
	r.Add(
		New("SURF-DMARC-005", "example.com"), // medium
		New("SURF-SPF-004", "example.com"),   // critical
		New("SURF-SPF-005", "example.com"),   // low
		New("SURF-DMARC-001", "example.com"), // high
	)
	r.Finalise()

	got := make([]Severity, 0, len(r.Findings))
	for _, f := range r.Findings {
		got = append(got, f.Severity)
	}
	assert.Equal(t, []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow,
	}, got, "findings must be ordered most severe first")
}

// TestFinaliseIsDeterministic protects the property that makes caching and
// drift detection possible: the same input must always produce the same order.
func TestFinaliseIsDeterministic(t *testing.T) {
	build := func() *Result {
		r := NewResult("vantage", "test")
		r.Add(
			New("SURF-DMARC-002", "b.example.com"),
			New("SURF-DMARC-002", "a.example.com"),
			New("SURF-SPF-003", "a.example.com"),
		)
		r.Finalise()
		return r
	}

	first, second := build(), build()
	require.Len(t, first.Findings, 3)
	for i := range first.Findings {
		assert.Equal(t, first.Findings[i].ID, second.Findings[i].ID)
		assert.Equal(t, first.Findings[i].Target, second.Findings[i].Target)
	}
	// Same severity, so the target is the tie-breaker.
	assert.Equal(t, "a.example.com", first.Findings[0].Target)
}

func TestSummaryCounts(t *testing.T) {
	r := NewResult("vantage", "test")
	r.Add(
		New("SURF-SPF-004", "example.com"),   // critical
		New("SURF-DMARC-001", "example.com"), // high
		New("SURF-DMARC-005", "example.com"), // medium
		New("SURF-SPF-005", "example.com"),   // low
	)
	r.Finalise()

	assert.Equal(t, 1, r.Summary.Critical)
	assert.Equal(t, 1, r.Summary.High)
	assert.Equal(t, 1, r.Summary.Medium)
	assert.Equal(t, 1, r.Summary.Low)
	assert.Equal(t, 4, r.Summary.Total)
}

// TestSuppressedFindingsAreExcludedFromCounts checks that suppression affects
// the counts without hiding the finding itself, so an auditor can still see
// what was accepted and why.
func TestSuppressedFindingsAreExcludedFromCounts(t *testing.T) {
	suppressed := New("SURF-SPF-004", "example.com")
	suppressed.Suppressed = true
	suppressed.SuppressionReason = "risk accepted"

	r := NewResult("vantage", "test")
	r.Add(suppressed, New("SURF-DMARC-002", "example.com"))
	r.Finalise()

	assert.Equal(t, 0, r.Summary.Critical)
	assert.Equal(t, 1, r.Summary.Suppressed)
	assert.Equal(t, 1, r.Summary.Total)
	assert.Len(t, r.Findings, 2, "suppressed findings must still be reported")
}

func TestMaxSeverityIgnoresSuppressed(t *testing.T) {
	critical := New("SURF-SPF-004", "example.com")
	critical.Suppressed = true

	r := NewResult("vantage", "test")
	r.Add(critical, New("SURF-DMARC-005", "example.com")) // medium
	r.Finalise()

	max, ok := r.MaxSeverity()
	require.True(t, ok)
	assert.Equal(t, SeverityMedium, max,
		"a suppressed critical must not drive the exit code")
}

func TestMaxSeverityOnEmptyResult(t *testing.T) {
	r := NewResult("vantage", "test")
	r.Finalise()

	_, ok := r.MaxSeverity()
	assert.False(t, ok)
}

func TestFilterAppliesThreshold(t *testing.T) {
	r := NewResult("vantage", "test")
	r.Add(
		New("SURF-SPF-004", "example.com"),   // critical
		New("SURF-DMARC-005", "example.com"), // medium
		New("SURF-SPF-005", "example.com"),   // low
	)
	r.Finalise()

	filtered := r.Filter(SeverityMedium)
	assert.Len(t, filtered.Findings, 2)
	assert.Len(t, r.Findings, 3, "Filter must not mutate the original result")
}

func TestAddTargetDeduplicates(t *testing.T) {
	r := NewResult("vantage", "test")
	r.AddTarget("example.com")
	r.AddTarget("example.com")
	r.AddTarget("other.example")

	assert.Equal(t, []string{"example.com", "other.example"}, r.Targets)
}

// TestCheckStatesAreDistinct is the honesty guarantee: "absent" and "not
// assessed" must never collapse into the same value, because a consumer acting
// on the first when the second is true reaches a false conclusion.
func TestCheckStatesAreDistinct(t *testing.T) {
	r := NewResult("vantage", "test")
	r.AddCheck("spf", "example.com", StateOK, "v=spf1 -all")
	r.AddCheck("dmarc", "example.com", StateNotFound)
	r.AddCheck("dkim", "example.com", StateNotChecked)
	r.AddCheck("mtasts", "example.com", StateCheckFailed)
	r.Finalise()

	states := map[string]State{}
	for _, c := range r.Checks {
		states[c.Check] = c.State
	}
	assert.Equal(t, StateOK, states["spf"])
	assert.Equal(t, StateNotFound, states["dmarc"])
	assert.Equal(t, StateNotChecked, states["dkim"])
	assert.Equal(t, StateCheckFailed, states["mtasts"])
	assert.NotEqual(t, states["dmarc"], states["dkim"])
}

func TestHasFailures(t *testing.T) {
	r := NewResult("vantage", "test")
	assert.False(t, r.HasFailures())

	r.AddError(CheckError{Check: "spf", Code: ErrCodeTimeout, Message: "timed out", Retryable: true})
	assert.True(t, r.HasFailures())
}

func TestSummaryDescribe(t *testing.T) {
	assert.Equal(t, "no findings", Summary{}.Describe())
	assert.Equal(t, "2 high, 1 medium", Summary{High: 2, Medium: 1}.Describe())
	assert.Equal(t, "1 critical, 3 info", Summary{Critical: 1, Info: 3}.Describe())
}

func TestSchemaVersionIsSet(t *testing.T) {
	r := NewResult("vantage", "test")
	assert.Equal(t, SchemaVersion, r.SchemaVersion)
	assert.Equal(t, "vantage", r.Tool.Name)
}

// Spec 013 diffs records between runs to detect drift and requires that false
// drift be avoidable. Records describing the run rather than the domain — a
// range file that was unreachable, the date data was fetched — change with
// network and cache state, so a differ has to be able to exclude them without
// pattern-matching prose that may later be reworded.
func TestIsDiagnosticRecord(t *testing.T) {
	assert.True(t, IsDiagnosticRecord("warning: provider ranges unavailable"))
	assert.True(t, IsDiagnosticRecord("provenance: Fastly ranges from https://x fetched 2026-08-03"))

	// Observations about the domain are the drift signal itself.
	assert.False(t, IsDiagnosticRecord("example.com 52.1.2.3 (Amazon Web Services)"))
	assert.False(t, IsDiagnosticRecord("v=spf1 -all"))
	assert.False(t, IsDiagnosticRecord(""))
	// The marker is a prefix, not a substring: a record merely mentioning a
	// warning is still an observation.
	assert.False(t, IsDiagnosticRecord("mx1.example.com warning: nothing"))
}

func TestObservedRecordsExcludesDiagnostics(t *testing.T) {
	c := CheckResult{Records: []string{
		"warning: provider ranges unavailable: Amazon Web Services",
		"example.com 52.1.2.3 (Amazon Web Services)",
		"provenance: Fastly ranges from https://x fetched 2026-08-03",
		"example.com 151.101.0.81 (Fastly)",
	}}

	assert.Equal(t, []string{
		"example.com 52.1.2.3 (Amazon Web Services)",
		"example.com 151.101.0.81 (Fastly)",
	}, c.ObservedRecords())

	// Order must be preserved: a differ comparing sequences would otherwise
	// see drift where only the filtering changed.
	assert.Equal(t, []string{}, CheckResult{}.ObservedRecords())
}
