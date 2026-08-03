package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseMTASTSRecord(t *testing.T) {
	tests := map[string]struct {
		record string
		want   MTASTSRecord
	}{
		"valid record": {
			record: "v=STSv1; id=20240101T000000Z",
			want:   MTASTSRecord{ID: "20240101T000000Z", Valid: true},
		},
		"case-insensitive version": {
			record: "V=stsv1; ID=abc",
			want:   MTASTSRecord{ID: "abc", Valid: true},
		},
		"no id is still structurally valid": {
			record: "v=STSv1",
			want:   MTASTSRecord{Valid: true},
		},
		"wrong version": {
			record: "v=spf1 -all",
			want: MTASTSRecord{
				Reason: "the record does not begin with the required v=STSv1 tag",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := ParseMTASTSRecord(tc.record)
			tc.want.Raw = tc.record
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseMTASTSPolicy(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n"
	got := ParseMTASTSPolicy(body)

	assert.True(t, got.Valid)
	assert.True(t, got.Fetched)
	assert.Equal(t, "enforce", got.Mode)
	assert.Equal(t, []string{"mail.example.com", "*.example.net"}, got.MX)
	assert.Equal(t, 604800, got.MaxAge)
}

func TestParseMTASTSPolicyHandlesCRLF(t *testing.T) {
	// RFC 8461 specifies CRLF line endings, so a parser that splits on LF
	// alone would leave a stray carriage return on every value.
	body := "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 604800\r\n"
	got := ParseMTASTSPolicy(body)

	assert.True(t, got.Valid)
	assert.Equal(t, "enforce", got.Mode)
	assert.Equal(t, []string{"mail.example.com"}, got.MX)
	assert.Equal(t, 604800, got.MaxAge)
}

func TestParseMTASTSPolicyRejectsIncomplete(t *testing.T) {
	tests := map[string]struct {
		body   string
		reason string
	}{
		"no version": {
			body:   "mode: enforce\nmx: mail.example.com\nmax_age: 604800\n",
			reason: "the policy does not declare version: STSv1",
		},
		"no mode": {
			body:   "version: STSv1\nmx: mail.example.com\nmax_age: 604800\n",
			reason: "the policy has no mode field",
		},
		"not a policy at all": {
			body:   "<html><body>404 Not Found</body></html>",
			reason: "the policy does not declare version: STSv1",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := ParseMTASTSPolicy(tc.body)
			assert.False(t, got.Valid)
			assert.Equal(t, tc.reason, got.Reason)
		})
	}
}

// TestMTASTSCovers pins down the wildcard rule of RFC 8461 §4.1. A leading
// "*." matches exactly one label; treating it as a broader wildcard would pass
// a policy that senders will reject, which is the opposite of useful.
func TestMTASTSCovers(t *testing.T) {
	tests := map[string]struct {
		pattern string
		host    string
		want    bool
	}{
		"exact match":                      {pattern: "mx.example.com", host: "mx.example.com", want: true},
		"exact match is case-insensitive":  {pattern: "MX.Example.COM", host: "mx.example.com", want: true},
		"trailing dots are normalised":     {pattern: "mx.example.com.", host: "mx.example.com", want: true},
		"exact mismatch":                   {pattern: "mx.example.com", host: "mx2.example.com", want: false},
		"wildcard matches one label":       {pattern: "*.example.com", host: "mx.example.com", want: true},
		"wildcard does not match two":      {pattern: "*.example.com", host: "a.mx.example.com", want: false},
		"wildcard does not match the apex": {pattern: "*.example.com", host: "example.com", want: false},
		"wildcard needs the right suffix":  {pattern: "*.example.com", host: "mx.example.net", want: false},
		"empty pattern":                    {pattern: "", host: "mx.example.com", want: false},
		"empty host":                       {pattern: "*.example.com", host: "", want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, MTASTSCovers(tc.pattern, tc.host))
		})
	}
}

func TestMTASTSNoRecord(t *testing.T) {
	got := ids(MTASTS(Origin{Target: "example.com"}, nil, MTASTSPolicy{}, nil))
	assert.Equal(t, []string{"SURF-MTASTS-001"}, got)
}

func TestMTASTSMalformedRecord(t *testing.T) {
	got := ids(MTASTS(Origin{Target: "example.com"},
		[]string{"v=STSv2; id=1"}, MTASTSPolicy{}, nil))
	assert.Equal(t, []string{"SURF-MTASTS-001"}, got)
}

// TestMTASTSWithoutFetchStopsAtDNS is the --no-network contract: the DNS-only
// conclusions stand, and nothing is invented about a policy never retrieved.
func TestMTASTSWithoutFetchStopsAtDNS(t *testing.T) {
	got := MTASTS(Origin{Target: "example.com"},
		[]string{"v=STSv1; id=1"}, MTASTSPolicy{}, []string{"mx.example.com"})
	assert.Empty(t, got, "an unfetched policy must not produce findings about its contents")
}

// TestMTASTSPolicyUnreachable is the failure the spec calls out: the domain
// looks protected and is not.
func TestMTASTSPolicyUnreachable(t *testing.T) {
	policy := MTASTSPolicy{Fetched: true, CertificateValid: true}
	got := ids(MTASTS(Origin{Target: "example.com"},
		[]string{"v=STSv1; id=1"}, policy, nil))
	assert.Equal(t, []string{"SURF-MTASTS-002"}, got)
}

// TestMTASTSInvalidCertificateIsReportedOverUnreachability keeps the finding
// actionable: the certificate is the cause, the unreachability the symptom.
func TestMTASTSInvalidCertificateIsReportedOverUnreachability(t *testing.T) {
	policy := MTASTSPolicy{Fetched: true, CertificateValid: false}
	got := ids(MTASTS(Origin{Target: "example.com"},
		[]string{"v=STSv1; id=1"}, policy, nil))
	assert.Equal(t, []string{"SURF-MTASTS-008"}, got)
}

func TestMTASTSModes(t *testing.T) {
	tests := map[string]struct {
		mode string
		want string
	}{
		"testing": {mode: "testing", want: "SURF-MTASTS-003"},
		"none":    {mode: "none", want: "SURF-MTASTS-004"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			policy := ParseMTASTSPolicy(
				"version: STSv1\nmode: " + tc.mode + "\nmx: mx.example.com\nmax_age: 604800\n")
			policy.CertificateValid = true

			got := ids(MTASTS(Origin{Target: "example.com"},
				[]string{"v=STSv1; id=1"}, policy, []string{"mx.example.com"}))
			assert.Equal(t, []string{tc.want}, got)
		})
	}
}

// TestMTASTSUncoveredMX is the adversarial case the spec asks for: an enforcing
// policy that omits a published exchanger causes mail to that host to bounce.
func TestMTASTSUncoveredMX(t *testing.T) {
	policy := ParseMTASTSPolicy(
		"version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n")
	policy.CertificateValid = true

	findings := MTASTS(Origin{Target: "example.com"}, []string{"v=STSv1; id=1"}, policy,
		[]string{"mx1.example.com", "mx2.example.com"})

	assert.Equal(t, []string{"SURF-MTASTS-005"}, ids(findings))

	var sawHost bool
	for _, f := range findings {
		for _, e := range f.Evidence {
			if e.Name == "mtasts.uncovered_mx" && e.Value == "mx2.example.com" {
				sawHost = true
			}
		}
	}
	assert.True(t, sawHost, "the operator needs to know which exchanger is uncovered")
}

func TestMTASTSWildcardCoversMX(t *testing.T) {
	policy := ParseMTASTSPolicy(
		"version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800\n")
	policy.CertificateValid = true

	got := MTASTS(Origin{Target: "example.com"}, []string{"v=STSv1; id=1"}, policy,
		[]string{"mx1.example.com", "mx2.example.com"})
	assert.Empty(t, got)
}

func TestMTASTSNullMXIsIgnored(t *testing.T) {
	policy := ParseMTASTSPolicy(
		"version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n")
	policy.CertificateValid = true

	got := MTASTS(Origin{Target: "example.com"}, []string{"v=STSv1; id=1"}, policy,
		[]string{"mx.example.com", "."})
	assert.Empty(t, got, "a null MX is not an exchanger the policy must cover")
}

func TestMTASTSIDMismatch(t *testing.T) {
	policy := ParseMTASTSPolicy(
		"version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\nid: 20240202T000000Z\n")
	policy.CertificateValid = true

	got := ids(MTASTS(Origin{Target: "example.com"},
		[]string{"v=STSv1; id=20240101T000000Z"}, policy, []string{"mx.example.com"}))
	assert.Equal(t, []string{"SURF-MTASTS-006"}, got)
}

func TestMTASTSShortMaxAge(t *testing.T) {
	policy := ParseMTASTSPolicy(
		"version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 3600\n")
	policy.CertificateValid = true

	got := ids(MTASTS(Origin{Target: "example.com"},
		[]string{"v=STSv1; id=1"}, policy, []string{"mx.example.com"}))
	assert.Equal(t, []string{"SURF-MTASTS-007"}, got)
}

func TestMTASTSHealthyDeploymentIsClean(t *testing.T) {
	policy := ParseMTASTSPolicy(
		"version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 604800\n")
	policy.CertificateValid = true

	got := MTASTS(Origin{Target: "example.com"}, []string{"v=STSv1; id=1"}, policy,
		[]string{"mx1.example.com", "mx2.example.com"})
	assert.Empty(t, got)
}
