package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func wildcardOrigin() Origin {
	return Origin{Target: "example.com", Source: "192.0.2.1:53"}
}

func addressProbes(addresses ...string) []WildcardProbe {
	return []WildcardProbe{
		{Label: "d1.example.com", Addresses: addresses},
		{Label: "d2.example.com", Addresses: addresses},
		{Label: "d3.example.com", Addresses: addresses},
	}
}

func TestWildcardAddressDetected(t *testing.T) {
	findings := Wildcard(wildcardOrigin(), WildcardObservation{
		Domain: "example.com",
		Probes: addressProbes("192.0.2.10"),
	})

	require.Len(t, findings, 1)
	assert.Equal(t, "DNSA-WILD-001", findings[0].ID)
	assert.Equal(t, "example.com", findings[0].Target)
}

// A single probe must never be enough. One name resolving proves that name
// exists, not that the zone answers for everything, and asserting a wildcard
// from it would suppress takeover findings on a zone that has none.
func TestWildcardRequiresAgreement(t *testing.T) {
	t.Run("one probe is not evidence", func(t *testing.T) {
		findings := Wildcard(wildcardOrigin(), WildcardObservation{
			Domain: "example.com",
			Probes: []WildcardProbe{{Label: "d1.example.com", Addresses: []string{"192.0.2.10"}}},
		})
		assert.Empty(t, findings)
	})

	t.Run("disagreeing probes are not a wildcard", func(t *testing.T) {
		findings := Wildcard(wildcardOrigin(), WildcardObservation{
			Domain: "example.com",
			Probes: []WildcardProbe{
				{Label: "d1.example.com", Addresses: []string{"192.0.2.10"}},
				{Label: "d2.example.com", Addresses: []string{"192.0.2.11"}},
			},
		})
		assert.Empty(t, findings)
	})

	t.Run("a probe that did not resolve is not a wildcard", func(t *testing.T) {
		findings := Wildcard(wildcardOrigin(), WildcardObservation{
			Domain: "example.com",
			Probes: []WildcardProbe{
				{Label: "d1.example.com", Addresses: []string{"192.0.2.10"}},
				{Label: "d2.example.com"},
			},
		})
		assert.Empty(t, findings)
	})
}

// Answer order is a property of the resolver, not of the zone, so two
// identical answer sets must compare equal however they arrive.
func TestWildcardIgnoresAnswerOrder(t *testing.T) {
	findings := Wildcard(wildcardOrigin(), WildcardObservation{
		Domain: "example.com",
		Probes: []WildcardProbe{
			{Label: "d1.example.com", Addresses: []string{"192.0.2.10", "192.0.2.11"}},
			{Label: "d2.example.com", Addresses: []string{"192.0.2.11", "192.0.2.10"}},
		},
	})

	require.Len(t, findings, 1)
	assert.Equal(t, "DNSA-WILD-001", findings[0].ID)
}

func TestWildcardMX(t *testing.T) {
	findings := Wildcard(wildcardOrigin(), WildcardObservation{
		Domain: "example.com",
		Probes: []WildcardProbe{
			{Label: "d1.example.com", MX: []string{"10 mail.example.com"}},
			{Label: "d2.example.com", MX: []string{"10 mail.example.com."}},
		},
	})

	require.Len(t, findings, 1)
	assert.Equal(t, "DNSA-WILD-002", findings[0].ID)
}

func TestWildcardCNAME(t *testing.T) {
	t.Run("third-party target is reported", func(t *testing.T) {
		findings := Wildcard(wildcardOrigin(), WildcardObservation{
			Domain: "example.com",
			Probes: []WildcardProbe{
				{Label: "d1.example.com", CNAME: "example.github.io"},
				{Label: "d2.example.com", CNAME: "example.github.io."},
			},
		})

		require.Len(t, findings, 1)
		assert.Equal(t, "DNSA-WILD-003", findings[0].ID)
	})

	// An alias staying inside the domain's own tree hands control to nobody,
	// so reporting it would be noise in a check whose value depends on being
	// quiet when nothing is wrong.
	t.Run("in-domain target is not reported", func(t *testing.T) {
		findings := Wildcard(wildcardOrigin(), WildcardObservation{
			Domain: "example.com",
			Probes: []WildcardProbe{
				{Label: "d1.example.com", CNAME: "www.example.com"},
				{Label: "d2.example.com", CNAME: "www.example.com"},
			},
		})

		assert.Empty(t, findings)
	})
}

func TestHasWildcardAddress(t *testing.T) {
	present := WildcardObservation{Domain: "example.com", Probes: addressProbes("192.0.2.10")}
	assert.True(t, present.HasWildcardAddress())

	absent := WildcardObservation{Domain: "example.com", Probes: addressProbes()}
	assert.False(t, absent.HasWildcardAddress())
}

func TestExternalTo(t *testing.T) {
	assert.True(t, externalTo("example.com", "example.github.io"))
	assert.False(t, externalTo("example.com", "a.example.com"))
	assert.False(t, externalTo("example.com", "example.com"))
	// A name merely ending in the domain's text is not inside its tree.
	assert.True(t, externalTo("example.com", "notexample.com"))
	assert.False(t, externalTo("", "example.com"))
}
