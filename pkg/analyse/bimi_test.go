package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBIMI(t *testing.T) {
	tests := map[string]struct {
		record string
		want   BIMIRecord
	}{
		"full record": {
			record: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
			want: BIMIRecord{
				Location:  "https://example.com/logo.svg",
				Authority: "https://example.com/vmc.pem",
				Valid:     true,
			},
		},
		"location only": {
			record: "v=BIMI1; l=https://example.com/logo.svg",
			want:   BIMIRecord{Location: "https://example.com/logo.svg", Valid: true},
		},
		"case-insensitive version and tags": {
			record: "V=BIMI1; L=https://example.com/logo.svg",
			want:   BIMIRecord{Location: "https://example.com/logo.svg", Valid: true},
		},
		"wrong version": {
			record: "v=spf1 -all",
			want: BIMIRecord{
				Reason: "the record does not begin with the required v=BIMI1 tag",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := ParseBIMI(tc.record)
			tc.want.Raw = tc.record
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestBIMIAbsenceIsNotAFinding keeps the tool honest: BIMI is optional
// branding, so not having it is not a security defect.
func TestBIMIAbsenceIsNotAFinding(t *testing.T) {
	assert.Empty(t, BIMI(Origin{Target: "example.com"}, nil, true))
}

// TestBIMIWithoutEnforcingDMARC is the rule that earns BIMI its place: the
// record is published, looks correct, and achieves nothing.
func TestBIMIWithoutEnforcingDMARC(t *testing.T) {
	records := []string{"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"}
	got := ids(BIMI(Origin{Target: "example.com"}, records, false))
	assert.Equal(t, []string{"DNSA-BIMI-001"}, got)
}

func TestBIMILogoNotHTTPS(t *testing.T) {
	tests := map[string]string{
		"plain http": "v=BIMI1; l=http://example.com/logo.svg; a=https://example.com/vmc.pem",
		"empty l":    "v=BIMI1; l=; a=https://example.com/vmc.pem",
		"missing l":  "v=BIMI1; a=https://example.com/vmc.pem",
	}

	for name, record := range tests {
		t.Run(name, func(t *testing.T) {
			got := ids(BIMI(Origin{Target: "example.com"}, []string{record}, true))
			assert.Equal(t, []string{"DNSA-BIMI-002"}, got)
		})
	}
}

func TestBIMIMissingVMC(t *testing.T) {
	records := []string{"v=BIMI1; l=https://example.com/logo.svg"}
	got := ids(BIMI(Origin{Target: "example.com"}, records, true))
	assert.Equal(t, []string{"DNSA-BIMI-003"}, got)
}

func TestBIMIMalformedRecord(t *testing.T) {
	got := ids(BIMI(Origin{Target: "example.com"}, []string{"not a bimi record"}, true))
	assert.Equal(t, []string{"DNSA-BIMI-002"}, got)
}

func TestBIMICompleteRecordIsClean(t *testing.T) {
	records := []string{"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"}
	assert.Empty(t, BIMI(Origin{Target: "example.com"}, records, true))
}
