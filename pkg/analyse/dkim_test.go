package analyse

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/finding"
)

// publicKey returns a base64 SubjectPublicKeyInfo RSA key of the given size, so
// the tests exercise the same parsing path a real record would.
func publicKey(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}

// weakRSAKey512 is a precomputed 512-bit RSA public key, checked in because Go
// 1.24 onwards refuses to generate keys this small: crypto/rsa returns
// "512-bit keys are insecure" from GenerateKey.
//
// The restriction is on generation, not parsing, so vantage can still detect
// weak keys published in the wild — which is the whole point of
// SURF-DKIM-002. Dropping this case to satisfy the toolchain would have
// removed coverage of a finding that still fires against real domains, so the
// key is embedded instead. It is a public key with no corresponding secret in
// the tree, and is never used to sign or verify anything.
const weakRSAKey512 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJMT2mUQEFNgsjfGwvqPtFarbBnq" +
	"azez5MEip5Vg7dr0skS8+sFxih0aGFK0VH3NGji8OVYrjdNn+RfgvtdgKdsCAwEAAQ=="

func TestParseDKIM(t *testing.T) {
	strong := publicKey(t, 2048)

	tests := map[string]struct {
		record   string
		valid    bool
		revoked  bool
		testMode bool
	}{
		"well-formed":           {record: "v=DKIM1; k=rsa; p=" + strong, valid: true},
		"revoked":               {record: "v=DKIM1; k=rsa; p=", valid: true, revoked: true},
		"test mode":             {record: "v=DKIM1; t=y; p=" + strong, valid: true, testMode: true},
		"test mode among flags": {record: "v=DKIM1; t=s:y; p=" + strong, valid: true, testMode: true},
		"missing p tag":         {record: "v=DKIM1; k=rsa"},
		"invalid base64":        {record: "v=DKIM1; p=not!base64!"},
		"not a public key":      {record: "v=DKIM1; p=" + base64.StdEncoding.EncodeToString([]byte("nonsense"))},
		"short ed25519 key":     {record: "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString([]byte("too short"))},
		"well-formed ed25519":   {record: "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(make([]byte, 32)), valid: true},
		"no tags at all":        {record: "gibberish"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key := ParseDKIM("selector1", tc.record)
			assert.Equal(t, tc.valid, key.Valid, "reason: %s", key.Reason)
			assert.Equal(t, tc.revoked, key.Revoked)
			assert.Equal(t, tc.testMode, key.TestMode)
			if !key.Valid {
				assert.NotEmpty(t, key.Reason, "an invalid record must explain why it was rejected")
			}
		})
	}
}

// TestParseDKIMWrappedKey guards the most common real-world defect: a key
// wrapped across lines by a DNS interface. The whitespace is presentational and
// must not be mistaken for invalid base64.
func TestParseDKIMWrappedKey(t *testing.T) {
	strong := publicKey(t, 2048)
	wrapped := strong[:40] + " " + strong[40:]

	key := ParseDKIM("selector1", "v=DKIM1; k=rsa; p="+wrapped)
	require.True(t, key.Valid, key.Reason)
	assert.Equal(t, 2048, key.Bits)
}

// TestParseDKIMWeakKeyIsStillParsable guards the detection of SURF-DKIM-002
// against the toolchain itself. Go restricts *generating* small RSA keys, and
// if a future release extended that to parsing, every weak key in the wild
// would silently become "malformed" instead of "weak" — downgrading a specific,
// actionable finding into a vague one, in the one case where the domain is
// genuinely at risk.
func TestParseDKIMWeakKeyIsStillParsable(t *testing.T) {
	key := ParseDKIM("selector1", "v=DKIM1; k=rsa; p="+weakRSAKey512)

	require.True(t, key.Valid, "a 512-bit key is weak, not malformed: %s", key.Reason)
	assert.Equal(t, 512, key.Bits, "the key size must be reported so it can be judged")
}

func TestDKIM(t *testing.T) {
	origin := Origin{Target: "example.com", Source: "192.0.2.1:53"}

	tests := map[string]struct {
		records map[string]string
		probed  bool
		wantIDs []string
	}{
		"no keys found by probing":    {probed: true, wantIDs: []string{"SURF-DKIM-001"}},
		"no key at supplied selector": {wantIDs: []string{"SURF-DKIM-001"}},
		"healthy 2048-bit key":        {records: map[string]string{"selector1": "v=DKIM1; k=rsa; p=" + publicKey(t, 2048)}},
		"1024-bit key":                {records: map[string]string{"selector1": "v=DKIM1; k=rsa; p=" + publicKey(t, 1024)}, wantIDs: []string{"SURF-DKIM-003"}},
		"512-bit key":                 {records: map[string]string{"selector1": "v=DKIM1; k=rsa; p=" + weakRSAKey512}, wantIDs: []string{"SURF-DKIM-002"}},
		"test mode":                   {records: map[string]string{"selector1": "v=DKIM1; t=y; p=" + publicKey(t, 2048)}, wantIDs: []string{"SURF-DKIM-005"}},
		// A revoked or malformed key leaves the domain with no usable key
		// either, so both findings are correct and both are needed.
		"revoked key":   {records: map[string]string{"selector1": "v=DKIM1; p="}, wantIDs: []string{"SURF-DKIM-001", "SURF-DKIM-004"}},
		"malformed key": {records: map[string]string{"selector1": "v=DKIM1; p=!!!"}, wantIDs: []string{"SURF-DKIM-001", "SURF-DKIM-006"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var keys []DKIMKey
			for selector, record := range tc.records {
				keys = append(keys, ParseDKIM(selector, record))
			}
			assert.ElementsMatch(t, tc.wantIDs, ids(DKIM(origin, keys, tc.probed)))
		})
	}
}

// TestDKIMAbsenceConfidence pins the distinction spec 011 insists upon: guessing
// selectors cannot disprove DKIM, so a probed absence must not be asserted with
// the same confidence as one at a selector the caller named.
func TestDKIMAbsenceConfidence(t *testing.T) {
	origin := Origin{Target: "example.com"}

	probed := DKIM(origin, nil, true)
	require.Len(t, probed, 1)
	assert.NotEqual(t, finding.ConfidenceHigh, probed[0].Confidence)

	explicit := DKIM(origin, nil, false)
	require.Len(t, explicit, 1)
	assert.Equal(t, finding.ConfidenceHigh, explicit[0].Confidence)
}

// TestDKIMHealthyKeyAlongsideRetiredOne checks that a retired selector does not
// mask a working one: the revocation is reported, but the domain is not also
// told it has no DKIM at all.
func TestDKIMHealthyKeyAlongsideRetiredOne(t *testing.T) {
	origin := Origin{Target: "example.com"}
	keys := []DKIMKey{
		ParseDKIM("selector1", "v=DKIM1; k=rsa; p="+publicKey(t, 2048)),
		ParseDKIM("selector2", "v=DKIM1; p="),
	}

	assert.ElementsMatch(t, []string{"SURF-DKIM-004"}, ids(DKIM(origin, keys, true)))
}
