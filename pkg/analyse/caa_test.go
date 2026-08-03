package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCAA(t *testing.T) {
	tests := map[string]struct {
		records []string
		want    []CAARecord
	}{
		"quotes are stripped": {
			records: []string{`0 issue "letsencrypt.org"`},
			want:    []CAARecord{{Flags: 0, Tag: "issue", Value: "letsencrypt.org"}},
		},
		"critical flag is preserved": {
			records: []string{`128 issue "letsencrypt.org"`},
			want:    []CAARecord{{Flags: 128, Tag: "issue", Value: "letsencrypt.org"}},
		},
		"tag is lowercased": {
			records: []string{`0 ISSUE "ca.example"`},
			want:    []CAARecord{{Flags: 0, Tag: "issue", Value: "ca.example"}},
		},
		"value may contain spaces": {
			records: []string{`0 issue "ca.example; account=12345"`},
			want:    []CAARecord{{Flags: 0, Tag: "issue", Value: "ca.example; account=12345"}},
		},
		"short records are skipped": {records: []string{"0 issue"}, want: nil},
		"empty input":               {records: nil, want: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseCAA(tc.records))
		})
	}
}

func TestCAARecordCritical(t *testing.T) {
	assert.True(t, CAARecord{Flags: 128}.Critical())
	assert.False(t, CAARecord{Flags: 0}.Critical())
	assert.False(t, CAARecord{Flags: 1}.Critical(), "only bit 0 is the critical flag")
}

// TestCAAAncestors covers the tree-climbing order of RFC 8659 §3. Climbing into
// the public suffix would attribute a registry's policy to an unrelated
// registrant, so the search must stop below it.
func TestCAAAncestors(t *testing.T) {
	tests := map[string]struct {
		domain string
		suffix string
		want   []string
	}{
		"deep subdomain climbs to the registrable domain": {
			domain: "a.b.example.com", suffix: "com",
			want: []string{"a.b.example.com", "b.example.com", "example.com"},
		},
		"registrable domain is the only name": {
			domain: "example.com", suffix: "com",
			want: []string{"example.com"},
		},
		"multi-label suffix is respected": {
			domain: "www.example.co.uk", suffix: "co.uk",
			want: []string{"www.example.co.uk", "example.co.uk"},
		},
		"trailing dots and case are normalised": {
			domain: "WWW.Example.COM.", suffix: "com",
			want: []string{"www.example.com", "example.com"},
		},
		"a public suffix itself has no policy to find": {
			domain: "com", suffix: "com", want: nil,
		},
		"empty domain": {domain: "", suffix: "com", want: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, CAAAncestors(tc.domain, tc.suffix))
		})
	}
}

func TestCAANoPolicyAnywhere(t *testing.T) {
	got := ids(CAA(Origin{Target: "example.com"}, CAAPolicy{}))
	assert.Equal(t, []string{"SURF-CAA-001"}, got)
}

func TestCAAInheritedPolicyIsReported(t *testing.T) {
	policy := CAAPolicy{
		Records: []CAARecord{
			{Tag: "issue", Value: "letsencrypt.org"},
			{Tag: "issuewild", Value: ";"},
			{Tag: "iodef", Value: "mailto:security@example.com"},
		},
		Source:    "example.com",
		Inherited: true,
	}
	got := ids(CAA(Origin{Target: "www.example.com"}, policy))
	assert.Equal(t, []string{"SURF-CAA-005"}, got)
}

func TestCAAIssueWithoutIssueWild(t *testing.T) {
	policy := CAAPolicy{
		Records: []CAARecord{
			{Tag: "issue", Value: "letsencrypt.org"},
			{Tag: "iodef", Value: "mailto:security@example.com"},
		},
		Source: "example.com",
	}
	got := ids(CAA(Origin{Target: "example.com"}, policy))
	assert.Equal(t, []string{"SURF-CAA-002"}, got)
}

func TestCAAMissingIodef(t *testing.T) {
	policy := CAAPolicy{
		Records: []CAARecord{
			{Tag: "issue", Value: "letsencrypt.org"},
			{Tag: "issuewild", Value: ";"},
		},
		Source: "example.com",
	}
	got := ids(CAA(Origin{Target: "example.com"}, policy))
	assert.Equal(t, []string{"SURF-CAA-003"}, got)
}

// TestCAACriticalUnknownTag is the case that breaks issuance entirely: a CA
// that cannot interpret a critical property must refuse to issue.
func TestCAACriticalUnknownTag(t *testing.T) {
	policy := CAAPolicy{
		Records: []CAARecord{
			{Tag: "issue", Value: "letsencrypt.org"},
			{Tag: "issuewild", Value: ";"},
			{Tag: "iodef", Value: "mailto:security@example.com"},
			{Flags: 128, Tag: "unknown-property", Value: "x"},
		},
		Source: "example.com",
	}
	got := ids(CAA(Origin{Target: "example.com"}, policy))
	assert.Equal(t, []string{"SURF-CAA-004"}, got)
}

func TestCAACriticalKnownTagIsFine(t *testing.T) {
	policy := CAAPolicy{
		Records: []CAARecord{
			{Flags: 128, Tag: "issue", Value: "letsencrypt.org"},
			{Tag: "issuewild", Value: ";"},
			{Tag: "iodef", Value: "mailto:security@example.com"},
		},
		Source: "example.com",
	}
	assert.Empty(t, CAA(Origin{Target: "example.com"}, policy))
}

func TestCAACompletePolicyIsClean(t *testing.T) {
	policy := CAAPolicy{
		Records: ParseCAA([]string{
			`0 issue "letsencrypt.org"`,
			`0 issuewild ";"`,
			`0 iodef "mailto:security@example.com"`,
		}),
		Source: "example.com",
	}
	assert.Empty(t, CAA(Origin{Target: "example.com"}, policy))
}
