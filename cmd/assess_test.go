package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
)

// captureRecords runs a record check and returns the records the result
// recorded for it, which is what a structured consumer would see.
func captureRecords(t *testing.T, target string, check recordCheck) ([]string, []string) {
	t.Helper()
	resetOutputFlags(t)
	showFindings = true

	result := newResult()
	result.AddTarget(target)

	records, source, err := check.retrieve(context.Background(), target)
	origin := analyse.Origin{Target: target, Source: source}
	require.NoError(t, err)

	var findings []finding.Finding
	if check.analyse != nil {
		findings = check.analyse(context.Background(), origin, records)
	}
	if check.evidence != nil {
		records = append(records, check.evidence()...)
	}
	result.AddCheck(check.name, target, finding.StateOK, records...)
	result.Add(findings...)

	var ids []string
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	return records, ids
}

// TestRecordCheckEvidenceIsRecorded pins the contract that material a check
// retrieves beyond DNS is reported alongside the DNS answers.
//
// Without this, a command could raise a finding derived from a policy file the
// operator never sees, making the verdict impossible to verify independently.
func TestRecordCheckEvidenceIsRecorded(t *testing.T) {
	fetched := false
	check := recordCheck{
		name: "stub",
		retrieve: func(ctx context.Context, target string) ([]string, string, error) {
			return []string{"v=STSv1; id=1"}, "192.0.2.1", nil
		},
		analyse: func(ctx context.Context, o analyse.Origin, records []string) []finding.Finding {
			fetched = true
			return nil
		},
		evidence: func() []string {
			if !fetched {
				return nil
			}
			return []string{"version: STSv1", "mode: enforce"}
		},
	}

	records, _ := captureRecords(t, "example.com", check)

	// The DNS record must come first, then the retrieved evidence, so the
	// chain from lookup to conclusion reads in order.
	assert.Equal(t, []string{
		"v=STSv1; id=1",
		"version: STSv1",
		"mode: enforce",
	}, records)
}

// TestRecordCheckEvidenceRunsAfterAnalyse guards the ordering the hook depends
// on: evidence is gathered during analyse, so calling it first would silently
// record nothing.
func TestRecordCheckEvidenceRunsAfterAnalyse(t *testing.T) {
	var order []string
	check := recordCheck{
		name: "stub",
		retrieve: func(ctx context.Context, target string) ([]string, string, error) {
			return []string{"record"}, "192.0.2.1", nil
		},
		analyse: func(ctx context.Context, o analyse.Origin, records []string) []finding.Finding {
			order = append(order, "analyse")
			return nil
		},
		evidence: func() []string {
			order = append(order, "evidence")
			return nil
		},
	}

	captureRecords(t, "example.com", check)
	assert.Equal(t, []string{"analyse", "evidence"}, order)
}

// TestPolicyLinesOmitsUnfetchedPolicy keeps --no-network runs honest: a policy
// that was never retrieved must contribute no evidence, rather than appearing
// as though it had been inspected.
func TestPolicyLinesOmitsUnfetchedPolicy(t *testing.T) {
	assert.Nil(t, policyLines(analyse.MTASTSPolicy{}))
	assert.Nil(t, policyLines(analyse.MTASTSPolicy{Raw: "version: STSv1", Fetched: false}))

	lines := policyLines(analyse.MTASTSPolicy{
		Fetched: true,
		Raw:     "version: STSv1\r\nmode: enforce\n\nmax_age: 86400\n",
	})
	// Blank lines and CRLF are stripped, so the evidence reads cleanly.
	assert.Equal(t, []string{"version: STSv1", "mode: enforce", "max_age: 86400"}, lines)
}

// TestIsNotFoundTreatsSentinelAsAbsence documents that a definitive "no such
// name" is a conclusion rather than a failure. Misreading it as an error has
// caused real false negatives in this tool.
func TestIsNotFoundTreatsSentinelAsAbsence(t *testing.T) {
	assert.True(t, isNotFound(vantage.ErrNotFound))
	assert.False(t, isNotFound(errors.New("server misbehaving")))
}
