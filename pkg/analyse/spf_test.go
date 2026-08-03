package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// ids extracts the finding IDs from a slice, for concise assertions.
func ids(findings []finding.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}

func TestSPFTerminalMechanisms(t *testing.T) {
	tests := map[string]struct {
		record   string
		wantIDs  []string
		wantNone bool
	}{
		"hard fail is correct": {
			record:   "v=spf1 include:_spf.example.com -all",
			wantNone: true,
		},
		"soft fail is flagged": {
			record:  "v=spf1 include:_spf.example.com ~all",
			wantIDs: []string{"DNSA-SPF-005"},
		},
		"neutral is flagged": {
			record:  "v=spf1 include:_spf.example.com ?all",
			wantIDs: []string{"DNSA-SPF-003"},
		},
		"pass all is critical": {
			record:  "v=spf1 include:_spf.example.com +all",
			wantIDs: []string{"DNSA-SPF-004"},
		},
		"bare all is pass all": {
			record:  "v=spf1 include:_spf.example.com all",
			wantIDs: []string{"DNSA-SPF-004"},
		},
		"missing terminal is flagged": {
			record:  "v=spf1 include:_spf.example.com",
			wantIDs: []string{"DNSA-SPF-003"},
		},
		"redirect excuses a missing terminal": {
			record:   "v=spf1 redirect=_spf.example.com",
			wantNone: true,
		},
		"case is ignored": {
			record:  "v=spf1 INCLUDE:_spf.example.com +ALL",
			wantIDs: []string{"DNSA-SPF-004"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := SPF(Origin{Target: "example.com"}, []string{tc.record}, true)
			if tc.wantNone {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.wantIDs, ids(got))
		})
	}
}

func TestSPFMissingRecord(t *testing.T) {
	t.Run("mail sending domain", func(t *testing.T) {
		got := SPF(Origin{Target: "example.com"}, nil, true)
		require.Len(t, got, 1)
		assert.Equal(t, "DNSA-SPF-001", got[0].ID)
		assert.Equal(t, finding.SeverityHigh, got[0].Severity)
	})

	// A domain that does not send mail is a much smaller prize. Reporting it as
	// High would be noise, and noise is what trains operators to ignore output.
	t.Run("non-mail domain is downgraded", func(t *testing.T) {
		got := SPF(Origin{Target: "example.com"}, nil, false)
		require.Len(t, got, 1)
		assert.Equal(t, finding.SeverityLow, got[0].Severity)
		assert.Contains(t, got[0].Description, "no MX records",
			"the downgrade must be explained")
	})
}

func TestSPFMultipleRecords(t *testing.T) {
	got := SPF(Origin{Target: "example.com"}, []string{
		"v=spf1 include:one.example -all",
		"v=spf1 include:two.example -all",
	}, true)

	assert.Contains(t, ids(got), "DNSA-SPF-002")
}

func TestSPFDeprecatedPTR(t *testing.T) {
	got := SPF(Origin{Target: "example.com"}, []string{"v=spf1 ptr:example.com -all"}, true)
	assert.Contains(t, ids(got), "DNSA-SPF-008")

	got = SPF(Origin{Target: "example.com"}, []string{"v=spf1 ptr -all"}, true)
	assert.Contains(t, ids(got), "DNSA-SPF-008")
}

func TestSPFBroadRanges(t *testing.T) {
	tests := map[string]struct {
		record string
		want   bool
	}{
		"slash 8 is too broad":     {record: "v=spf1 ip4:10.0.0.0/8 -all", want: true},
		"slash 15 is too broad":    {record: "v=spf1 ip4:10.0.0.0/15 -all", want: true},
		"slash 16 is acceptable":   {record: "v=spf1 ip4:10.0.0.0/16 -all", want: false},
		"slash 24 is fine":         {record: "v=spf1 ip4:192.0.2.0/24 -all", want: false},
		"single address is fine":   {record: "v=spf1 ip4:192.0.2.1 -all", want: false},
		"malformed cidr is benign": {record: "v=spf1 ip4:not-an-ip/8 -all", want: false},
		"broad ipv6":               {record: "v=spf1 ip6:2001:db8::/24 -all", want: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := ids(SPF(Origin{Target: "example.com"}, []string{tc.record}, true))
			if tc.want {
				assert.Contains(t, got, "DNSA-SPF-011")
				return
			}
			assert.NotContains(t, got, "DNSA-SPF-011")
		})
	}
}

func TestSPFFindingsCarryEvidence(t *testing.T) {
	got := SPF(Origin{Target: "example.com"}, []string{"v=spf1 +all"}, true)
	require.NotEmpty(t, got)
	require.NotEmpty(t, got[0].Evidence, "every finding must justify itself")
	assert.Equal(t, "v=spf1 +all", got[0].Evidence[0].Value)
}
