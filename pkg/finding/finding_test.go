package finding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogueIntegrity is the guard that keeps the catalogue trustworthy.
// Every entry must be fully populated, because a finding without remediation
// guidance or a reference tells the reader there is a problem but not what to
// do about it, which is barely better than saying nothing.
func TestCatalogueIntegrity(t *testing.T) {
	require.NoError(t, ValidateCatalogue())
	assert.NotEmpty(t, Catalogue(), "the catalogue must not be empty")
}

func TestCatalogueIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range Catalogue() {
		assert.False(t, seen[e.ID], "duplicate catalogue ID %s", e.ID)
		seen[e.ID] = true
	}
}

func TestCatalogueIsSorted(t *testing.T) {
	entries := Catalogue()
	for i := 1; i < len(entries); i++ {
		assert.Less(t, entries[i-1].ID, entries[i].ID,
			"Catalogue() must return entries in ID order")
	}
}

func TestCatalogueForCheck(t *testing.T) {
	spf := CatalogueForCheck("spf")
	require.NotEmpty(t, spf)
	for _, e := range spf {
		assert.Equal(t, "spf", e.Check)
	}
	assert.Empty(t, CatalogueForCheck("nonexistent"))
}

func TestChecks(t *testing.T) {
	checks := Checks()
	assert.Contains(t, checks, "spf")
	assert.Contains(t, checks, "dmarc")
}

func TestSeverityRoundTrip(t *testing.T) {
	for _, sev := range []Severity{
		SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical,
	} {
		data, err := json.Marshal(sev)
		require.NoError(t, err)

		var back Severity
		require.NoError(t, json.Unmarshal(data, &back))
		assert.Equal(t, sev, back, "severity %s did not survive a JSON round trip", sev)
	}
}

func TestSeverityOrdering(t *testing.T) {
	// Ordering underpins --severity and --fail-on, so it is worth asserting
	// explicitly rather than trusting the iota declaration order.
	assert.Greater(t, SeverityCritical, SeverityHigh)
	assert.Greater(t, SeverityHigh, SeverityMedium)
	assert.Greater(t, SeverityMedium, SeverityLow)
	assert.Greater(t, SeverityLow, SeverityInfo)
}

func TestParseSeverity(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    Severity
		wantErr bool
	}{
		"lower case":     {input: "high", want: SeverityHigh},
		"upper case":     {input: "HIGH", want: SeverityHigh},
		"with spaces":    {input: "  medium  ", want: SeverityMedium},
		"critical":       {input: "critical", want: SeverityCritical},
		"unknown value":  {input: "severe", wantErr: true},
		"empty string":   {input: "", wantErr: true},
		"numeric string": {input: "3", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseSeverity(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseConfidence(t *testing.T) {
	got, err := ParseConfidence("Medium")
	require.NoError(t, err)
	assert.Equal(t, ConfidenceMedium, got)

	_, err = ParseConfidence("certain")
	assert.Error(t, err)
}

// TestZeroValuesAreSafe guards a deliberate design choice: an unset severity
// must present as Info, not Critical, so that a forgotten field can never
// manufacture a false alarm.
func TestZeroValuesAreSafe(t *testing.T) {
	var f Finding
	assert.Equal(t, SeverityInfo, f.Severity)
	assert.Equal(t, ConfidenceLow, f.Confidence)
}

func TestNewFromCatalogue(t *testing.T) {
	f := New("DNSA-SPF-004", "example.com",
		DNSEvidence("example.com", "TXT", "v=spf1 +all", "1.1.1.1:53"))

	entry, ok := Lookup("DNSA-SPF-004")
	require.True(t, ok)

	assert.Equal(t, entry.Title, f.Title)
	assert.Equal(t, entry.Severity, f.Severity)
	assert.Equal(t, entry.Remediation, f.Remediation)
	assert.Equal(t, "example.com", f.Target)
	assert.Equal(t, "spf", f.Check)
	require.Len(t, f.Evidence, 1)
	assert.Equal(t, "v=spf1 +all", f.Evidence[0].Value)
}

func TestNewPanicsOnUnknownID(t *testing.T) {
	// An unknown ID is a programming error. Failing loudly in tests is far
	// better than emitting a finding with no title or guidance at runtime.
	assert.Panics(t, func() { New("DNSA-NOPE-001", "example.com") })
}

func TestWithSeverityRecordsTheReason(t *testing.T) {
	f := New("DNSA-SPF-001", "example.com").
		WithSeverity(SeverityLow, "Reduced because the domain sends no mail.")

	assert.Equal(t, SeverityLow, f.Severity)
	assert.Contains(t, f.Description, "Reduced because the domain sends no mail.",
		"an adjusted severity must explain itself")
}
