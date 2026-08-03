package netattr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJurisdictionOfKnownRegions(t *testing.T) {
	cases := map[string]string{
		"eu-west-1":      "IE",
		"eu-west-2":      "GB",
		"eu-central-1":   "DE",
		"us-east-1":      "US",
		"ap-southeast-2": "AU",
		"europe-west2":   "GB",
		"europe-west1":   "BE",
		"asia-east1":     "TW",
	}
	for region, want := range cases {
		assert.Equal(t, want, JurisdictionOf(region), region)
	}
}

// Google publishes a scope that is sometimes a zone and sometimes a region;
// both must resolve to the same country.
func TestJurisdictionOfNormalisesGoogleZones(t *testing.T) {
	assert.Equal(t, "GB", JurisdictionOf("europe-west2-a"))
	assert.Equal(t, "GB", JurisdictionOf("europe-west2"))
}

// An AWS region ends in a digit and must not be mistaken for a zone and
// truncated, which would turn eu-west-2 into eu-west and lose the answer.
func TestJurisdictionOfDoesNotTruncateAWSRegions(t *testing.T) {
	assert.Equal(t, "GB", JurisdictionOf("eu-west-2"))
	assert.Equal(t, "US", JurisdictionOf("us-east-1"))
}

// An unknown region yields nothing rather than a guess. Inferring a country
// from the region name's prefix — that "eu-" means the EU — would be wrong for
// the UK and Switzerland, which are exactly the cases a data-residency question
// is asked about.
func TestJurisdictionOfUnknownRegionIsEmpty(t *testing.T) {
	assert.Empty(t, JurisdictionOf("moon-north-1"))
	assert.Empty(t, JurisdictionOf(""))
	assert.Empty(t, JurisdictionOf("eu-atlantis-9"))
}

// A publication that parses to nothing must be an error. An operator changing
// its file format would otherwise leave every one of its addresses silently
// unattributed, which reads exactly like that operator hosting nothing.
func TestParsersRejectAnEmptyPublication(t *testing.T) {
	_, err := parseAWS([]byte(`{"prefixes":[],"ipv6_prefixes":[]}`))
	assert.Error(t, err)

	_, err = parseGCP([]byte(`{"prefixes":[]}`))
	assert.Error(t, err)

	_, err = parsePlainList([]byte("# comment only\n\n"))
	assert.Error(t, err)

	_, err = parseFastly([]byte(`{"addresses":[],"ipv6_addresses":[]}`))
	assert.Error(t, err)
}

func TestParseAWSReadsRegions(t *testing.T) {
	ranges, err := parseAWS([]byte(`{
		"prefixes": [{"ip_prefix": "52.94.0.0/16", "region": "eu-west-1"}],
		"ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/24", "region": "us-east-1"}]
	}`))
	require.NoError(t, err)
	require.Len(t, ranges, 2)
	assert.Equal(t, "eu-west-1", ranges[0].Region)
	assert.Equal(t, "us-east-1", ranges[1].Region)
}

// A malformed prefix inside an otherwise good publication is skipped rather
// than failing the whole file: losing one range is better than losing an
// operator's entire attribution.
func TestParseAWSSkipsMalformedPrefixes(t *testing.T) {
	ranges, err := parseAWS([]byte(`{
		"prefixes": [
			{"ip_prefix": "not-a-prefix", "region": "eu-west-1"},
			{"ip_prefix": "52.94.0.0/16", "region": "eu-west-1"}
		]
	}`))
	require.NoError(t, err)
	assert.Len(t, ranges, 1)
}

func TestParsePlainListIgnoresCommentsAndBlanks(t *testing.T) {
	ranges, err := parsePlainList([]byte("# Cloudflare\n\n173.245.48.0/20\n103.21.244.0/22\n"))
	require.NoError(t, err)
	assert.Len(t, ranges, 2)
}
