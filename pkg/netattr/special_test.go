package netattr

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The registry drives the one rule in this check that carries real severity,
// so each category must be recognised for what it is.
func TestLookupSpecialClassifies(t *testing.T) {
	cases := map[string]struct {
		addr     string
		category Category
	}{
		"RFC 1918 ten":         {"10.1.2.3", CategoryPrivate},
		"RFC 1918 172":         {"172.20.0.1", CategoryPrivate},
		"RFC 1918 192.168":     {"192.168.1.1", CategoryPrivate},
		"carrier-grade NAT":    {"100.64.0.1", CategoryCGNAT},
		"loopback":             {"127.0.0.1", CategoryLoopback},
		"link local":           {"169.254.169.254", CategoryLinkLocal},
		"documentation":        {"192.0.2.1", CategoryDocumentation},
		"benchmarking":         {"198.18.0.1", CategoryDocumentation},
		"reserved":             {"240.0.0.1", CategoryReserved},
		"unspecified":          {"0.0.0.0", CategoryUnspecified},
		"multicast":            {"224.0.0.1", CategorySpecial},
		"IPv6 loopback":        {"::1", CategoryLoopback},
		"IPv6 unique local":    {"fd00::1", CategoryPrivate},
		"IPv6 link local":      {"fe80::1", CategoryLinkLocal},
		"IPv6 documentation":   {"2001:db8::1", CategoryDocumentation},
		"IPv6 unspecified":     {"::", CategoryUnspecified},
		"IPv4-mapped loopback": {"::ffff:127.0.0.1", CategoryLoopback},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			require.NoError(t, err)

			sr, ok := LookupSpecial(addr)
			require.True(t, ok, "%s should be special-purpose space", tc.addr)
			assert.Equal(t, tc.category, sr.Category)
			assert.NotEmpty(t, sr.Reference, "every entry must cite the RFC that reserved it")
		})
	}
}

// Ordinary public addresses must not be classified, or every host on the
// internet would be reported as leaking internal addressing.
func TestLookupSpecialLeavesGlobalUnicastAlone(t *testing.T) {
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"} {
		addr := netip.MustParseAddr(raw)
		_, ok := LookupSpecial(addr)
		assert.False(t, ok, "%s should not be special-purpose space", raw)
		assert.True(t, IsGlobalUnicast(addr))
	}
}

// Only the categories that genuinely disclose an internal addressing plan
// should be treated as leakage. Loopback is deliberately excluded: pointing a
// name at 127.0.0.1 to make it exist without resolving anywhere is a recognised
// practice, not a disclosure.
func TestDisclosesInternalAddressing(t *testing.T) {
	assert.True(t, CategoryPrivate.DisclosesInternalAddressing())
	assert.True(t, CategoryCGNAT.DisclosesInternalAddressing())
	assert.True(t, CategoryLinkLocal.DisclosesInternalAddressing())

	assert.False(t, CategoryLoopback.DisclosesInternalAddressing())
	assert.False(t, CategoryUnspecified.DisclosesInternalAddressing())
	assert.False(t, CategoryDocumentation.DisclosesInternalAddressing())
}

// Operators publish overlapping prefixes — a regional range inside a global
// aggregate — so the most specific announcement must win. Taking the first
// match would report the aggregate's region for an address placed elsewhere.
func TestLookupPrefersTheMostSpecificPrefix(t *testing.T) {
	set := Set{Providers: []Provider{{
		Name:   "Example Cloud",
		Source: "https://example.test/ranges.json",
		Ranges: []ProviderRange{
			{Prefix: netip.MustParsePrefix("203.0.0.0/8"), Region: "us-east-1"},
			{Prefix: netip.MustParsePrefix("203.10.0.0/16"), Region: "eu-west-1"},
		},
	}}}

	a := set.Lookup(netip.MustParseAddr("203.10.5.5"))
	assert.Equal(t, "Example Cloud", a.Provider)
	assert.Equal(t, "eu-west-1", a.Region)
	assert.Equal(t, "IE", a.Jurisdiction)
	assert.True(t, a.Attributed())
}

// Special-purpose space short-circuits provider matching: an RFC 1918 address
// cannot also be an operator's announced range, and a provider file claiming
// otherwise would be wrong.
func TestLookupPrefersSpecialUseOverProviderRanges(t *testing.T) {
	set := Set{Providers: []Provider{{
		Name:   "Example Cloud",
		Ranges: []ProviderRange{{Prefix: netip.MustParsePrefix("10.0.0.0/8")}},
	}}}

	a := set.Lookup(netip.MustParseAddr("10.1.1.1"))
	require.NotNil(t, a.Special)
	assert.Equal(t, CategoryPrivate, a.Special.Category)
	assert.Empty(t, a.Provider)
}

// An address nobody claims must be reported as unattributed. Coverage is
// incomplete by construction — Azure publishes no stable endpoint — so
// "unattributed" and "not in a cloud" are different statements and only the
// first is one this package can make.
func TestLookupUnattributedAddressMakesNoClaim(t *testing.T) {
	set := Set{Providers: []Provider{{
		Name:   "Example Cloud",
		Ranges: []ProviderRange{{Prefix: netip.MustParsePrefix("203.0.113.0/24")}},
	}}}

	a := set.Lookup(netip.MustParseAddr("198.51.100.7"))
	assert.False(t, a.Attributed() && a.Provider != "")
	assert.Empty(t, a.Provider)
}

func TestSetCompleteReportsFailedSources(t *testing.T) {
	assert.True(t, Set{}.Complete())
	assert.False(t, Set{Failed: []string{"Example"}}.Complete())
}
