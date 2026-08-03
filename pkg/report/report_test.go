package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// sample builds a representative result: several severities, evidence, a check
// state and a failed check.
func sample() *finding.Result {
	r := finding.NewResult("dnsaudit", "v1.0.0-test")
	r.AddTarget("example.com")
	r.Add(
		finding.New("DNSA-SPF-004", "example.com",
			finding.DNSEvidence("example.com", "TXT", "v=spf1 +all", "1.1.1.1:53")),
		finding.New("DNSA-DMARC-002", "example.com",
			finding.DNSEvidence("_dmarc.example.com", "TXT", "v=DMARC1; p=none", "1.1.1.1:53")),
	)
	r.AddCheck("spf", "example.com", finding.StateOK, "v=spf1 +all")
	r.AddCheck("dmarc", "example.com", finding.StateOK, "v=DMARC1; p=none")
	r.AddCheck("dkim", "example.com", finding.StateNotChecked)
	r.AddError(finding.CheckError{
		Check: "mtasts", Target: "example.com", Code: finding.ErrCodeTimeout,
		Message: "error: timed out", Retryable: true, RetryAfterSeconds: 5,
	})
	r.Finalise()
	return r
}

func render(t *testing.T, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, Render(&buf, sample(), opts))
	return buf.String()
}

func TestParseFormat(t *testing.T) {
	for _, name := range Formats() {
		got, err := ParseFormat(name)
		require.NoError(t, err)
		assert.Equal(t, Format(name), got)
	}

	got, err := ParseFormat("  JSON  ")
	require.NoError(t, err)
	assert.Equal(t, FormatJSON, got)

	_, err = ParseFormat("xml")
	assert.Error(t, err)
}

func TestFormatStructured(t *testing.T) {
	assert.False(t, FormatText.Structured())
	assert.True(t, FormatJSON.Structured())
	assert.True(t, FormatSARIF.Structured())
}

func TestRenderTextIncludesEvidenceAndRemediation(t *testing.T) {
	out := render(t, Options{Format: FormatText})

	assert.Contains(t, out, "CRITICAL")
	assert.Contains(t, out, "DNSA-SPF-004")
	assert.Contains(t, out, "v=spf1 +all", "text output must show the evidence")
	assert.Contains(t, out, "Fix:", "text output must show the remediation")
	assert.Contains(t, out, "Posture:")
	assert.Contains(t, out, "Checks that could not complete:")
}

// TestRenderTextOrdersMostSevereFirst matters for usability: the reader's
// attention is finite and should land on the worst problem.
func TestRenderTextOrdersMostSevereFirst(t *testing.T) {
	out := render(t, Options{Format: FormatText})
	assert.Less(t, strings.Index(out, "DNSA-SPF-004"), strings.Index(out, "DNSA-DMARC-002"))
}

func TestRenderTextHasNoColourByDefault(t *testing.T) {
	out := render(t, Options{Format: FormatText})
	assert.NotContains(t, out, "\033[", "colour must be opt-in")
}

func TestRenderJSONIsValidAndComplete(t *testing.T) {
	out := render(t, Options{Format: FormatJSON})

	var result finding.Result
	require.NoError(t, json.Unmarshal([]byte(out), &result),
		"JSON output must be parseable")

	assert.Equal(t, finding.SchemaVersion, result.SchemaVersion)
	assert.Equal(t, "dnsaudit", result.Tool.Name)
	assert.Equal(t, []string{"example.com"}, result.Targets)
	assert.Len(t, result.Findings, 2)
	assert.Equal(t, 1, result.Summary.Critical)
	assert.Len(t, result.Errors, 1)
	assert.True(t, result.Errors[0].Retryable,
		"the retry hint must survive serialisation")
}

// TestRenderJSONRoundTrips guards the contract that a consumer can read our
// output back into the same structure.
func TestRenderJSONRoundTrips(t *testing.T) {
	out := render(t, Options{Format: FormatJSON})

	var result finding.Result
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.Equal(t, finding.SeverityCritical, result.Findings[0].Severity,
		"severity must round trip as a name, not an integer")
}

func TestRenderNDJSONEmitsOneObjectPerLine(t *testing.T) {
	out := render(t, Options{Format: FormatNDJSON})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.GreaterOrEqual(t, len(lines), 4)

	kinds := make([]string, 0, len(lines))
	for _, line := range lines {
		var obj map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"every NDJSON line must be a standalone JSON object")
		kind, ok := obj["kind"].(string)
		require.True(t, ok, "every NDJSON record must be tagged with a kind")
		kinds = append(kinds, kind)
	}

	assert.Equal(t, "meta", kinds[0], "the metadata record must come first")
	assert.Contains(t, kinds, "finding")
	assert.Contains(t, kinds, "check")
	assert.Contains(t, kinds, "error")
}

func TestRenderCSVHasHeaderAndRows(t *testing.T) {
	out := render(t, Options{Format: FormatCSV})

	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 3, "one header row plus two findings")
	assert.Equal(t, csvHeader, rows[0])
	assert.Equal(t, "DNSA-SPF-004", rows[1][1])
	assert.Equal(t, "critical", rows[1][2])
}

func TestRenderSARIFIsWellFormed(t *testing.T) {
	out := render(t, Options{Format: FormatSARIF})

	var log map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &log))
	assert.Equal(t, "2.1.0", log["version"])

	runs, ok := log["runs"].([]any)
	require.True(t, ok)
	require.Len(t, runs, 1)
	run, ok := runs[0].(map[string]any)
	require.True(t, ok)

	tool, ok := run["tool"].(map[string]any)
	require.True(t, ok)
	driver, ok := tool["driver"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "dnsaudit", driver["name"])
	rules, ok := driver["rules"].([]any)
	require.True(t, ok)
	assert.Len(t, rules, 2)

	results, ok := run["results"].([]any)
	require.True(t, ok)
	require.Len(t, results, 2)
	first, ok := results[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "DNSA-SPF-004", first["ruleId"])
	assert.Equal(t, "error", first["level"], "critical must map to the SARIF error level")
}

func TestMinSeverityFilters(t *testing.T) {
	out := render(t, Options{Format: FormatJSON, MinSeverity: finding.SeverityHigh})

	var result finding.Result
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "DNSA-SPF-004", result.Findings[0].ID)
}

func TestSummaryOmitsDetail(t *testing.T) {
	out := render(t, Options{Format: FormatJSON, Summary: true})

	var envelope map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &envelope))

	assert.Contains(t, envelope, "summary")
	assert.Contains(t, envelope, "finding_ids")
	assert.NotContains(t, envelope, "findings",
		"--summary must omit the full findings array")
}

// TestNoCatalogueTextTrimsProse verifies the token-economy option removes only
// the prose, leaving the identifiers a consumer needs to resolve it later.
func TestNoCatalogueTextTrimsProse(t *testing.T) {
	out := render(t, Options{Format: FormatJSON, NoCatalogueText: true})

	var result finding.Result
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	require.NotEmpty(t, result.Findings)

	assert.Empty(t, result.Findings[0].Description)
	assert.Empty(t, result.Findings[0].Remediation)
	assert.NotEmpty(t, result.Findings[0].ID, "the ID must survive so guidance stays resolvable")
	assert.NotEmpty(t, result.Findings[0].Title)
}

func TestFieldsProjection(t *testing.T) {
	out := render(t, Options{Format: FormatJSON, Fields: []string{"severity"}})

	var result finding.Result
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	require.NotEmpty(t, result.Findings)

	f := result.Findings[0]
	assert.Equal(t, finding.SeverityCritical, f.Severity)
	assert.Empty(t, f.Title)
	// ID and target are never projected away: without them the finding is not
	// interpretable at all.
	assert.Equal(t, "DNSA-SPF-004", f.ID)
	assert.Equal(t, "example.com", f.Target)
}

func TestRenderIsDeterministic(t *testing.T) {
	first := render(t, Options{Format: FormatJSON})
	second := render(t, Options{Format: FormatJSON})

	// Timestamps differ between constructions, so compare the findings only.
	var a, b finding.Result
	require.NoError(t, json.Unmarshal([]byte(first), &a))
	require.NoError(t, json.Unmarshal([]byte(second), &b))

	require.Len(t, a.Findings, len(b.Findings))
	for i := range a.Findings {
		assert.Equal(t, a.Findings[i].ID, b.Findings[i].ID)
	}
}

func TestRenderEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	empty := finding.NewResult("dnsaudit", "test")
	empty.AddTarget("clean.example")

	require.NoError(t, Render(&buf, empty, Options{Format: FormatText}))
	assert.Contains(t, buf.String(), "no findings")
}

func TestUnknownFormatIsRejected(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, sample(), Options{Format: Format("toml")})
	assert.Error(t, err)
}

func TestFieldNamesAreStable(t *testing.T) {
	assert.Equal(t, FieldNames(), FieldNames())
	assert.Contains(t, FieldNames(), "severity")
}
