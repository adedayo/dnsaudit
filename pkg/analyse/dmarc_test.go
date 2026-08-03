package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

func TestParseDMARC(t *testing.T) {
	t.Run("full record", func(t *testing.T) {
		p := ParseDMARC("v=DMARC1; p=reject; sp=quarantine; pct=50; " +
			"rua=mailto:agg@example.com,mailto:second@example.com; " +
			"ruf=mailto:forensic@example.com; adkim=s; aspf=r")

		require.True(t, p.Valid)
		assert.Equal(t, "reject", p.Policy)
		assert.Equal(t, "quarantine", p.Subdomain)
		assert.Equal(t, 50, p.Percent)
		assert.Equal(t, []string{"mailto:agg@example.com", "mailto:second@example.com"}, p.RUA)
		assert.Equal(t, []string{"mailto:forensic@example.com"}, p.RUF)
		assert.Equal(t, "s", p.ADKIM)
	})

	t.Run("pct defaults to 100", func(t *testing.T) {
		p := ParseDMARC("v=DMARC1; p=reject")
		require.True(t, p.Valid)
		assert.Equal(t, 100, p.Percent)
	})

	t.Run("tolerates whitespace and case", func(t *testing.T) {
		p := ParseDMARC("  V=DMARC1 ;  P=Reject ;  ")
		require.True(t, p.Valid)
		assert.Equal(t, "reject", p.Policy)
	})

	invalid := map[string]string{
		"missing version":  "p=reject",
		"missing policy":   "v=DMARC1; rua=mailto:a@example.com",
		"unknown policy":   "v=DMARC1; p=block",
		"empty record":     "",
		"not dmarc at all": "v=spf1 -all",
	}
	for name, record := range invalid {
		t.Run("invalid: "+name, func(t *testing.T) {
			p := ParseDMARC(record)
			assert.False(t, p.Valid)
			assert.NotEmpty(t, p.Reason, "an invalid record must explain why")
		})
	}
}

func TestDMARCMissingRecord(t *testing.T) {
	got := DMARC(Origin{Target: "example.com"}, nil)
	require.Len(t, got, 1)
	assert.Equal(t, "DNSA-DMARC-001", got[0].ID)
	assert.Equal(t, finding.SeverityHigh, got[0].Severity)
}

func TestDMARCPolicies(t *testing.T) {
	tests := map[string]struct {
		record      string
		wantIDs     []string
		unwantedIDs []string
	}{
		"reject with reporting is clean": {
			record:      "v=DMARC1; p=reject; rua=mailto:a@example.com",
			unwantedIDs: []string{"DNSA-DMARC-002", "DNSA-DMARC-005"},
		},
		"monitoring only": {
			record:  "v=DMARC1; p=none; rua=mailto:a@example.com",
			wantIDs: []string{"DNSA-DMARC-002"},
		},
		"no aggregate reporting": {
			record:  "v=DMARC1; p=reject",
			wantIDs: []string{"DNSA-DMARC-005"},
		},
		"partial application": {
			record:  "v=DMARC1; p=reject; pct=20; rua=mailto:a@example.com",
			wantIDs: []string{"DNSA-DMARC-003"},
		},
		"weaker subdomain policy": {
			record:  "v=DMARC1; p=reject; sp=none; rua=mailto:a@example.com",
			wantIDs: []string{"DNSA-DMARC-004"},
		},
		"equal subdomain policy is fine": {
			record:      "v=DMARC1; p=reject; sp=reject; rua=mailto:a@example.com",
			unwantedIDs: []string{"DNSA-DMARC-004"},
		},
		"stronger subdomain policy is fine": {
			record:      "v=DMARC1; p=quarantine; sp=reject; rua=mailto:a@example.com",
			unwantedIDs: []string{"DNSA-DMARC-004"},
		},
		"invalid record": {
			record:  "v=DMARC1; rua=mailto:a@example.com",
			wantIDs: []string{"DNSA-DMARC-008"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := ids(DMARC(Origin{Target: "example.com"}, []string{tc.record}))
			for _, want := range tc.wantIDs {
				assert.Contains(t, got, want)
			}
			for _, unwanted := range tc.unwantedIDs {
				assert.NotContains(t, got, unwanted)
			}
		})
	}
}

// TestDMARCPctOnlyMattersWhenEnforcing checks a deliberate subtlety: pct is
// meaningless under p=none, so reporting it there would be noise.
func TestDMARCPctOnlyMattersWhenEnforcing(t *testing.T) {
	got := ids(DMARC(Origin{Target: "example.com"}, []string{
		"v=DMARC1; p=none; pct=20; rua=mailto:a@example.com",
	}))
	assert.NotContains(t, got, "DNSA-DMARC-003")
}

func TestDMARCMultipleRecords(t *testing.T) {
	got := ids(DMARC(Origin{Target: "example.com"}, []string{
		"v=DMARC1; p=reject; rua=mailto:a@example.com",
		"v=DMARC1; p=none",
	}))
	assert.Contains(t, got, "DNSA-DMARC-007")
}

func TestDMARCInvalidRecordExplainsItself(t *testing.T) {
	got := DMARC(Origin{Target: "example.com"}, []string{"v=DMARC1; p=block"})
	require.Len(t, got, 1)
	assert.Equal(t, "DNSA-DMARC-008", got[0].ID)
	assert.Contains(t, got[0].Description, "unrecognised value")
}

func TestDMARCEvidenceNamesTheQuery(t *testing.T) {
	got := DMARC(Origin{Target: "example.com"}, nil)
	require.NotEmpty(t, got)
	require.NotEmpty(t, got[0].Evidence)
	assert.Equal(t, "_dmarc.example.com", got[0].Evidence[0].Name,
		"evidence must name the record actually queried")
}
