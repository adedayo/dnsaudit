package analyse

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/dnsaudit/pkg/netattr"
)

func netIDs(t *testing.T, obs NetworkObservation) []string {
	t.Helper()
	var ids []string
	for _, f := range NetworkAttribution(Origin{Target: obs.Domain}, obs) {
		ids = append(ids, f.ID)
	}
	return ids
}

func special(t *testing.T, addr string) netattr.Attribution {
	t.Helper()
	a := netip.MustParseAddr(addr)
	sr, ok := netattr.LookupSpecial(a)
	require.True(t, ok, "%s should be special-purpose space", addr)
	return netattr.Attribution{Address: a, Special: &sr}
}

// A public name resolving into RFC 1918 space is the rule here that carries
// real severity, and it must be stated at full confidence.
func TestNetworkAttributionReportsPrivateAddressLeakage(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Hosts: []NetworkHost{{
			Host: "intranet.example.com", Role: "host",
			Attributions: []netattr.Attribution{special(t, "10.1.2.3")},
		}},
	}

	findings := NetworkAttribution(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 1)
	assert.Equal(t, "DNSA-NET-002", findings[0].ID)
	assert.Equal(t, "high", findings[0].Confidence.String())
}

// Null-routing a name at the loopback address is a recognised practice, not a
// disclosure. It is worth surfacing for confirmation but must not be asserted
// with the confidence of a leak.
func TestNetworkAttributionDownConfidencesNullRouting(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Hosts: []NetworkHost{{
			Host: "unused.example.com", Role: "host",
			Attributions: []netattr.Attribution{special(t, "127.0.0.1")},
		}},
	}

	findings := NetworkAttribution(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 1)
	assert.Equal(t, "DNSA-NET-002", findings[0].ID)
	assert.Equal(t, "low", findings[0].Confidence.String())
}

// An ordinary public address that no provider claims must produce nothing.
// Provider coverage is incomplete by construction, so an unattributed address
// supports no conclusion at all — least of all that the host is somewhere it
// should not be.
func TestNetworkAttributionSaysNothingAboutUnattributedAddresses(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Estate: map[string]bool{"Amazon Web Services": true},
		Hosts: []NetworkHost{{
			Host: "www.example.com", Role: "host",
			Attributions: []netattr.Attribution{{Address: netip.MustParseAddr("93.184.216.34")}},
		}},
	}
	assert.Empty(t, netIDs(t, obs))
}

// A host at a provider that serves none of the domain's own infrastructure is
// the inventory observation the rule exists for.
// A coverage gap produces false negatives, not false positives: an address
// whose provider file was unavailable reads as unattributed, DNSA-NET-001
// stops firing, and the report looks like a domain with no third-party
// hosting. Reproduced live against amazon.com with the AWS ranges withheld:
// every address rendered "(unattributed)" and nothing said why.
func TestNetworkRecordsDiscloseIncompleteCoverage(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Hosts: []NetworkHost{{
			Host: "www.example.com", Role: "apex",
			Attributions: []netattr.Attribution{
				{Address: netip.MustParseAddr("52.1.2.3")},
			},
		}},
		FailedSources: []string{"Amazon Web Services (https://ip-ranges.amazonaws.com/ip-ranges.json)"},
	}

	require.False(t, obs.CoverageComplete())
	records := NetworkRecords(obs)

	// The warning has to come before the data it qualifies.
	require.NotEmpty(t, records)
	assert.Contains(t, records[0], "attribution incomplete")
	assert.Contains(t, records[0], "Amazon Web Services")

	// "unattributed" asserts the address belongs to no known provider. That is
	// exactly what could not be established here, so it must not be claimed.
	assert.Contains(t, records[1], "coverage incomplete")
	assert.NotContains(t, records[1], "(unattributed)")
}

// With every source loaded, an address in no known range genuinely is
// unattributed, and the report should say so plainly without a caveat.
func TestNetworkRecordsSayUnattributedWhenCoverageIsComplete(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Hosts: []NetworkHost{{
			Host: "www.example.com", Role: "apex",
			Attributions: []netattr.Attribution{
				{Address: netip.MustParseAddr("93.184.216.34")},
			},
		}},
	}

	require.True(t, obs.CoverageComplete())
	records := NetworkRecords(obs)

	require.Len(t, records, 1)
	assert.Contains(t, records[0], "(unattributed)")
	assert.NotContains(t, records[0], "coverage incomplete")
}

func TestNetworkAttributionReportsHostOutsideTheEstate(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Estate: map[string]bool{"Amazon Web Services": true},
		Hosts: []NetworkHost{{
			Host: "marketing.example.com", Role: "host",
			Attributions: []netattr.Attribution{{
				Address:  netip.MustParseAddr("34.1.2.3"),
				Provider: "Google Cloud",
				Prefix:   netip.MustParsePrefix("34.0.0.0/8"),
				Source:   "https://www.gstatic.com/ipranges/cloud.json",
			}},
		}},
	}
	assert.Equal(t, []string{"DNSA-NET-001"}, netIDs(t, obs))
}

// A host with several addresses at one provider is one fact about that host.
// Reporting it once per address buries every other finding in the report: a
// live run against a domain with 90 CT-discovered hosts produced 262 identical
// findings before this was grouped.
func TestNetworkAttributionReportsAHostOnceRegardlessOfAddressCount(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Estate: map[string]bool{"Amazon Web Services": true},
		Hosts: []NetworkHost{{
			Host: "marketing.example.com", Role: "host",
			Attributions: []netattr.Attribution{
				{
					Address: netip.MustParseAddr("34.1.2.3"), Provider: "Google Cloud",
					Prefix: netip.MustParsePrefix("34.0.0.0/8"), Region: "europe-west1",
				},
				{
					Address: netip.MustParseAddr("34.4.5.6"), Provider: "Google Cloud",
					Prefix: netip.MustParsePrefix("34.0.0.0/8"), Region: "europe-west1",
				},
				{
					Address: netip.MustParseAddr("35.7.8.9"), Provider: "Google Cloud",
					Prefix: netip.MustParsePrefix("35.0.0.0/8"), Region: "us-east1",
				},
			},
		}},
	}

	findings := NetworkAttribution(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 1)

	// Grouping must not cost evidence: every address, prefix and region still
	// has to appear, or the reader loses the ability to verify the claim.
	values := map[string]string{}
	var addresses []string
	for _, e := range findings[0].Evidence {
		if e.Kind == "computed" {
			values[e.Name] = e.Value
			continue
		}
		addresses = append(addresses, e.Value)
	}
	assert.ElementsMatch(t, []string{"34.1.2.3", "34.4.5.6", "35.7.8.9"}, addresses)
	assert.Equal(t, "Google Cloud", values["net.provider"])
	assert.Equal(t, "34.0.0.0/8, 35.0.0.0/8", values["net.prefix"])
	assert.Equal(t, "europe-west1, us-east1", values["net.region"])
}

// Two providers for one host are two separate facts and must stay separate:
// grouping by host alone would hide the second one.
func TestNetworkAttributionReportsEachProviderOfAHostSeparately(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Estate: map[string]bool{"Amazon Web Services": true},
		Hosts: []NetworkHost{{
			Host: "marketing.example.com", Role: "host",
			Attributions: []netattr.Attribution{
				{
					Address: netip.MustParseAddr("34.1.2.3"), Provider: "Google Cloud",
					Prefix: netip.MustParsePrefix("34.0.0.0/8"),
				},
				{
					Address: netip.MustParseAddr("104.16.1.1"), Provider: "Cloudflare",
					Prefix: netip.MustParsePrefix("104.16.0.0/13"),
				},
			},
		}},
	}

	findings := NetworkAttribution(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 2)

	var providers []string
	for _, f := range findings {
		for _, e := range f.Evidence {
			if e.Name == "net.provider" {
				providers = append(providers, e.Value)
			}
		}
	}
	assert.ElementsMatch(t, []string{"Google Cloud", "Cloudflare"}, providers)
}

// Each private address is a distinct disclosure, so these are not grouped.
func TestNetworkAttributionReportsEveryLeakedPrivateAddress(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Hosts: []NetworkHost{{
			Host: "tools.example.com", Role: "host",
			Attributions: []netattr.Attribution{
				special(t, "10.1.2.3"),
				special(t, "10.1.2.4"),
			},
		}},
	}
	assert.Equal(t, []string{"DNSA-NET-002", "DNSA-NET-002"}, netIDs(t, obs))
}

// A host inside the estate is not remarkable and must not be reported, or the
// rule would fire on every well-run domain.
func TestNetworkAttributionIsQuietInsideTheEstate(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Estate: map[string]bool{"Amazon Web Services": true},
		Hosts: []NetworkHost{{
			Host: "www.example.com", Role: "host",
			Attributions: []netattr.Attribution{{
				Address:  netip.MustParseAddr("52.1.2.3"),
				Provider: "Amazon Web Services",
				Prefix:   netip.MustParsePrefix("52.0.0.0/8"),
			}},
		}},
	}
	assert.Empty(t, netIDs(t, obs))
}

// With no estate established there is nothing to be outside of, so the rule
// must not fire. Otherwise a domain whose apex could not be resolved would have
// every one of its hosts reported as foreign.
func TestNetworkAttributionNeedsAnEstateBeforeJudgingOne(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Hosts: []NetworkHost{{
			Host: "www.example.com", Role: "host",
			Attributions: []netattr.Attribution{{
				Address: netip.MustParseAddr("34.1.2.3"), Provider: "Google Cloud",
			}},
		}},
	}
	assert.Empty(t, netIDs(t, obs))
}

// The jurisdiction rule compares against a declared expectation. Without one
// there is nothing to compare, and a finding drawn from an assumed default
// would be an invention.
func TestNetworkAttributionJurisdictionNeedsAnExpectation(t *testing.T) {
	host := NetworkHost{
		Host: "www.example.com", Role: "host",
		Attributions: []netattr.Attribution{{
			Address:      netip.MustParseAddr("52.1.2.3"),
			Provider:     "Amazon Web Services",
			Region:       "us-east-1",
			Jurisdiction: "US",
		}},
	}

	obs := NetworkObservation{
		Domain: "example.com",
		Estate: map[string]bool{"Amazon Web Services": true},
		Hosts:  []NetworkHost{host},
	}
	assert.Empty(t, netIDs(t, obs))

	obs.ExpectedJurisdictions = []string{"GB", "IE"}
	assert.Equal(t, []string{"DNSA-NET-003"}, netIDs(t, obs))

	obs.ExpectedJurisdictions = []string{"gb", "us"} // case must not matter
	assert.Empty(t, netIDs(t, obs))
}

// An unknown region yields no jurisdiction, and no jurisdiction must yield no
// finding: "we could not tell where this is" is not evidence that it is in the
// wrong place.
func TestNetworkAttributionUnknownJurisdictionIsNotAViolation(t *testing.T) {
	obs := NetworkObservation{
		Domain:                "example.com",
		Estate:                map[string]bool{"Amazon Web Services": true},
		ExpectedJurisdictions: []string{"GB"},
		Hosts: []NetworkHost{{
			Host: "www.example.com", Role: "host",
			Attributions: []netattr.Attribution{{
				Address:  netip.MustParseAddr("52.1.2.3"),
				Provider: "Amazon Web Services",
				Region:   "moon-north-1",
			}},
		}},
	}
	assert.Empty(t, netIDs(t, obs))
}

// Multicast and broadcast addresses in an A record are certainly wrong, but
// they are a functional defect rather than a disclosure, and this check's remit
// is attribution.
func TestNetworkAttributionIgnoresNonDisclosingSpecialRanges(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Hosts: []NetworkHost{{
			Host: "odd.example.com", Role: "host",
			Attributions: []netattr.Attribution{special(t, "224.0.0.1")},
		}},
	}
	assert.Empty(t, netIDs(t, obs))
}

func TestNetworkRecordsShowWhatWasAttributed(t *testing.T) {
	obs := NetworkObservation{
		Domain: "example.com",
		Hosts: []NetworkHost{{
			Host: "www.example.com", Role: "apex",
			Attributions: []netattr.Attribution{
				{Address: netip.MustParseAddr("52.1.2.3"), Provider: "Amazon Web Services", Region: "eu-west-1"},
				{Address: netip.MustParseAddr("93.184.216.34")},
			},
		}},
	}

	records := NetworkRecords(obs)
	require.Len(t, records, 2)
	assert.Contains(t, records[0], "Amazon Web Services, eu-west-1")
	// A reader must be able to tell an address nobody claims from one that was
	// never looked at.
	assert.Contains(t, records[1], "unattributed")
}
