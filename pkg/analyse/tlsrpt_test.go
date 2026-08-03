package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLSRPT(t *testing.T) {
	origin := Origin{Target: "example.com", Source: "192.0.2.1:53"}

	tests := map[string]struct {
		records []string
		wantIDs []string
	}{
		"no record":            {wantIDs: []string{"SURF-TLSRPT-001"}},
		"mailto destination":   {records: []string{"v=TLSRPTv1; rua=mailto:tls@example.com"}},
		"https destination":    {records: []string{"v=TLSRPTv1; rua=https://reports.example.com/tls"}},
		"several destinations": {records: []string{"v=TLSRPTv1; rua=mailto:a@example.com,mailto:b@example.com"}},
		"missing rua":          {records: []string{"v=TLSRPTv1;"}, wantIDs: []string{"SURF-TLSRPT-002"}},
		// A scheme senders do not implement delivers no reports, so the record
		// buys the operator nothing but false assurance.
		"unsupported scheme": {records: []string{"v=TLSRPTv1; rua=ftp://example.com/reports"}, wantIDs: []string{"SURF-TLSRPT-002"}},
		"wrong version tag":  {records: []string{"v=TLSRPTv2; rua=mailto:tls@example.com"}, wantIDs: []string{"SURF-TLSRPT-002"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.wantIDs, ids(TLSRPT(origin, tc.records)))
		})
	}
}

// TestTLSRPTEvidenceNamesTheQuery keeps the finding reproducible: a reader must
// be able to see which name was queried without re-running the tool.
func TestTLSRPTEvidenceNamesTheQuery(t *testing.T) {
	findings := TLSRPT(Origin{Target: "example.com", Source: "192.0.2.1:53"}, nil)
	assert.Equal(t, "_smtp._tls.example.com", findings[0].Evidence[0].Name)
	assert.Equal(t, "192.0.2.1:53", findings[0].Evidence[0].Source)
}
