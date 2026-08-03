package analyse

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedNow anchors expiry arithmetic so the tests describe the boundary
// conditions rather than the moment they happen to run.
var fixedNow = time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

// encode renders raw key material as the base64 a DNSKEY record carries.
func encode(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// dnssecIDs returns the catalogue IDs raised for a zone.
func dnssecIDs(z DNSSECZone) []string {
	var out []string
	for _, f := range DNSSEC(Origin{Target: "example.com"}, z) {
		out = append(out, f.ID)
	}
	return out
}

// signedZone is a well-configured baseline that individual tests perturb, so
// each case shows exactly the defect under test and nothing else.
func signedZone() DNSSECZone {
	return DNSSECZone{
		Keys: []DNSKEY{{KeyTag: 1234, Flags: 257, Algorithm: 13}},
		DS:   []DS{{KeyTag: 1234, Algorithm: 13, DigestType: 2}},
		Signatures: []RRSIG{{
			TypeCovered: "SOA", Algorithm: 13, KeyTag: 1234,
			Expiration: fixedNow.Add(30 * 24 * time.Hour),
			Inception:  fixedNow.Add(-24 * time.Hour),
		}},
		NSEC3:             true,
		NSEC3Iterations:   0,
		AuthenticatedData: true,
		Now:               fixedNow,
	}
}

func TestDNSSECWellConfiguredZoneRaisesNothing(t *testing.T) {
	assert.Empty(t, dnssecIDs(signedZone()))
}

func TestDNSSECNotEnabled(t *testing.T) {
	assert.Equal(t, []string{"DNSA-DNSSEC-001"},
		dnssecIDs(DNSSECZone{Now: fixedNow}))
}

// TestDNSSECIslandOfTrust covers the case the tool exists to catch: signing is
// switched on, so every superficial check reports success, yet without a DS at
// the parent no resolver ever validates the zone.
func TestDNSSECIslandOfTrust(t *testing.T) {
	z := signedZone()
	z.DS = nil

	assert.Equal(t, []string{"DNSA-DNSSEC-002"}, dnssecIDs(z))
}

func TestDNSSECBrokenChain(t *testing.T) {
	tests := map[string]func(*DNSSECZone){
		"DS with no DNSKEY at all": func(z *DNSSECZone) { z.Keys = nil },
		"DS names a key tag the zone does not publish": func(z *DNSSECZone) {
			z.DS = []DS{{KeyTag: 9999, Algorithm: 13, DigestType: 2}}
		},
		"DS algorithm differs from the published key": func(z *DNSSECZone) {
			z.DS = []DS{{KeyTag: 1234, Algorithm: 8, DigestType: 2}}
		},
		"digest does not match the key it names": func(z *DNSSECZone) {
			z.DS = []DS{{KeyTag: 1234, Algorithm: 13, DigestType: 2, DigestMismatch: true}}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			z := signedZone()
			mutate(&z)
			assert.Contains(t, dnssecIDs(z), "DNSA-DNSSEC-003")
		})
	}
}

// TestDNSSECDigestMismatchDefaultsToTrusting guards the collector contract: a
// DS whose digest was never recomputed must not be reported as broken, because
// "we did not check" is not evidence of a fault.
func TestDNSSECDigestMismatchDefaultsToTrusting(t *testing.T) {
	z := signedZone()
	z.DS = []DS{{KeyTag: 1234, Algorithm: 13, DigestType: 2}}

	assert.NotContains(t, dnssecIDs(z), "DNSA-DNSSEC-003")
}

func TestDNSSECWeakAlgorithms(t *testing.T) {
	tests := map[string]struct {
		algorithm uint8
		want      bool
	}{
		"RSASHA1":            {algorithm: 5, want: true},
		"RSASHA1-NSEC3-SHA1": {algorithm: 7, want: true},
		"RSAMD5":             {algorithm: 1, want: true},
		"DSA":                {algorithm: 3, want: true},
		"RSASHA256":          {algorithm: 8, want: false},
		"ECDSAP256SHA256":    {algorithm: 13, want: false},
		"ED25519":            {algorithm: 15, want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			z := signedZone()
			z.Keys = []DNSKEY{{KeyTag: 1234, Flags: 257, Algorithm: tc.algorithm}}
			z.DS = []DS{{KeyTag: 1234, Algorithm: tc.algorithm, DigestType: 2}}

			if tc.want {
				assert.Contains(t, dnssecIDs(z), "DNSA-DNSSEC-004")
				return
			}
			assert.NotContains(t, dnssecIDs(z), "DNSA-DNSSEC-004")
		})
	}
}

// TestDNSSECWeakAlgorithmReportedOnce keeps the report proportionate: a zone
// signed with one deprecated algorithm has one problem, not one per key.
func TestDNSSECWeakAlgorithmReportedOnce(t *testing.T) {
	z := signedZone()
	z.Keys = []DNSKEY{
		{KeyTag: 1234, Flags: 257, Algorithm: 5},
		{KeyTag: 5678, Flags: 256, Algorithm: 5},
	}
	z.DS = []DS{{KeyTag: 1234, Algorithm: 5, DigestType: 2}}

	var weak int
	for _, id := range dnssecIDs(z) {
		if id == "DNSA-DNSSEC-004" {
			weak++
		}
	}
	assert.Equal(t, 1, weak)
}

func TestDNSSECSignatureExpiry(t *testing.T) {
	tests := map[string]struct {
		expiration time.Time
		want       []string
	}{
		"comfortably valid": {expiration: fixedNow.Add(30 * 24 * time.Hour)},
		"expiring in six days": {
			expiration: fixedNow.Add(6 * 24 * time.Hour),
			want:       []string{"DNSA-DNSSEC-005"},
		},
		"exactly on the seven-day boundary": {
			expiration: fixedNow.Add(7 * 24 * time.Hour),
			want:       []string{"DNSA-DNSSEC-005"},
		},
		"just outside the boundary": {
			expiration: fixedNow.Add(7*24*time.Hour + time.Minute),
		},
		"expired": {
			expiration: fixedNow.Add(-time.Hour),
			want:       []string{"DNSA-DNSSEC-006"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			z := signedZone()
			z.Signatures = []RRSIG{{TypeCovered: "SOA", KeyTag: 1234, Expiration: tc.expiration}}

			assert.Equal(t, tc.want, dnssecIDs(z))
		})
	}
}

// TestDNSSECExpiredAndExpiringReportedSeparately covers a zone mid-failure:
// some signatures have lapsed while others are about to, and both facts matter.
func TestDNSSECExpiredAndExpiringReportedSeparately(t *testing.T) {
	z := signedZone()
	z.Signatures = []RRSIG{
		{TypeCovered: "SOA", KeyTag: 1234, Expiration: fixedNow.Add(-time.Hour)},
		{TypeCovered: "DNSKEY", KeyTag: 1234, Expiration: fixedNow.Add(2 * 24 * time.Hour)},
	}

	assert.ElementsMatch(t,
		[]string{"DNSA-DNSSEC-005", "DNSA-DNSSEC-006"}, dnssecIDs(z))
}

// TestDNSSECZeroExpirationIsIgnored guards against inventing a critical outage
// from a signature whose expiry was simply not collected.
func TestDNSSECZeroExpirationIsIgnored(t *testing.T) {
	z := signedZone()
	z.Signatures = []RRSIG{{TypeCovered: "SOA", KeyTag: 1234}}

	assert.Empty(t, dnssecIDs(z))
}

func TestDNSSECDenialOfExistence(t *testing.T) {
	tests := map[string]struct {
		nsec, nsec3 bool
		synthesised bool
		iterations  int
		want        []string
	}{
		"NSEC3 with zero iterations is correct": {nsec3: true},
		"NSEC permits zone walking": {
			nsec: true, want: []string{"DNSA-DNSSEC-007"},
		},
		"synthesised NSEC cannot be walked": {
			nsec: true, synthesised: true,
		},
		"NSEC3 with extra iterations": {
			nsec3: true, iterations: 10, want: []string{"DNSA-DNSSEC-008"},
		},
		"a zone serving both is judged on NSEC3": {
			nsec: true, nsec3: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			z := signedZone()
			z.NSEC, z.NSEC3, z.NSEC3Iterations = tc.nsec, tc.nsec3, tc.iterations
			z.NSECSynthesised = tc.synthesised

			assert.Equal(t, tc.want, dnssecIDs(z))
		})
	}
}

// TestDNSSECEvidenceRecordsResolverValidation covers the reporting requirement
// that a reader can tell "the zone is signed" from "my resolver validates it".
func TestDNSSECEvidenceRecordsResolverValidation(t *testing.T) {
	z := signedZone()
	z.DS = nil
	z.AuthenticatedData = false

	findings := DNSSEC(Origin{Target: "example.com"}, z)
	require.Len(t, findings, 1)

	var found bool
	for _, e := range findings[0].Evidence {
		if e.Name == "dnssec.resolver_ad" {
			found = true
			assert.Equal(t, "false", e.Value)
		}
	}
	assert.True(t, found, "every DNSSEC finding must state whether the resolver validated")
}

// TestDNSKEYKeyBits covers RFC 3110 key material, including the short-exponent
// encoding used by essentially every real key and the long form that is easy to
// get wrong.
func TestDNSKEYKeyBits(t *testing.T) {
	// One-byte exponent length, three-byte exponent, then the modulus.
	short := func(modulusBytes int) string {
		raw := append([]byte{3, 1, 0, 1}, make([]byte, modulusBytes)...)
		// A non-zero leading octet, so no padding is stripped.
		raw[4] = 0xC0
		return encode(raw)
	}

	tests := map[string]struct {
		key  DNSKEY
		want int
	}{
		"2048-bit RSA": {
			key:  DNSKEY{Algorithm: 8, PublicKey: short(256)},
			want: 2048,
		},
		"1024-bit RSA": {
			key:  DNSKEY{Algorithm: 8, PublicKey: short(128)},
			want: 1024,
		},
		"elliptic curve keys have no reportable modulus": {
			key:  DNSKEY{Algorithm: 13, PublicKey: short(256)},
			want: 0,
		},
		"unparseable key material": {
			key:  DNSKEY{Algorithm: 8, PublicKey: "not base64!!"},
			want: 0,
		},
		"empty key material": {key: DNSKEY{Algorithm: 8}, want: 0},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.key.KeyBits())
		})
	}
}

// TestDNSSECUndersizedRSAKey covers the size threshold rather than the
// algorithm: RSASHA256 is a perfectly good algorithm used with too small a key.
func TestDNSSECUndersizedRSAKey(t *testing.T) {
	raw := append([]byte{3, 1, 0, 1}, make([]byte, 128)...)
	raw[4] = 0xC0

	z := signedZone()
	z.Keys = []DNSKEY{{KeyTag: 1234, Flags: 257, Algorithm: 8, PublicKey: encode(raw)}}
	z.DS = []DS{{KeyTag: 1234, Algorithm: 8, DigestType: 2}}

	assert.Contains(t, dnssecIDs(z), "DNSA-DNSSEC-004")
}

func TestDNSKEYFlags(t *testing.T) {
	ksk := DNSKEY{Flags: 257}
	assert.True(t, ksk.IsZoneKey())
	assert.True(t, ksk.IsSecureEntryPoint())

	zsk := DNSKEY{Flags: 256}
	assert.True(t, zsk.IsZoneKey())
	assert.False(t, zsk.IsSecureEntryPoint())
}

func TestDNSSECRecordsSummarisesTheZone(t *testing.T) {
	records := DNSSECRecords(signedZone())

	require.NotEmpty(t, records)
	assert.Contains(t, records[0], "keytag 1234")
	assert.Contains(t, records[0], "ECDSAP256SHA256")
	assert.Contains(t, records[0], "(KSK)")

	joined := ""
	for _, r := range records {
		joined += r + "\n"
	}
	assert.Contains(t, joined, "NSEC3")
	assert.Contains(t, joined, "Resolver AD bit: true")
}

func TestDNSSECRecordsForAnUnsignedZone(t *testing.T) {
	assert.Nil(t, DNSSECRecords(DNSSECZone{}))
}
