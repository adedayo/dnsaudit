package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func healthy(host string, addresses ...string) Nameserver {
	return Nameserver{
		Host: host, Addresses: addresses,
		Answered: true, Authoritative: true,
		Serial: 2026080301, HasSerial: true,
		RecursionTested: true,
	}
}

func delegationFindingIDs(t *testing.T, d Delegation) []string {
	t.Helper()
	var ids []string
	for _, f := range DelegationHygiene(Origin{Target: d.Domain}, d) {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestDelegationHealthyZoneIsSilent(t *testing.T) {
	d := Delegation{
		Domain: "example.com",
		Nameservers: []Nameserver{
			healthy("ns1.provider.net", "192.0.2.1"),
			healthy("ns2.provider.net", "198.51.100.1"),
		},
		ParentNS:      []string{"ns1.provider.net", "ns2.provider.net"},
		ParentChecked: true,
	}

	assert.Empty(t, delegationFindingIDs(t, d))
}

func TestDelegationSingleNameserver(t *testing.T) {
	d := Delegation{
		Domain:      "example.com",
		Nameservers: []Nameserver{healthy("ns1.provider.net", "192.0.2.1")},
	}

	// One nameserver must raise NS-001 and *not* also raise NS-003: a single
	// server trivially occupies a single /24, and two findings for one defect
	// would overstate the problem.
	assert.Equal(t, []string{"SURF-NS-001"}, delegationFindingIDs(t, d))
}

func TestDelegationSingleNetwork(t *testing.T) {
	t.Run("same /24 is reported", func(t *testing.T) {
		d := Delegation{
			Domain: "example.com",
			Nameservers: []Nameserver{
				healthy("ns1.provider.net", "192.0.2.1"),
				healthy("ns2.provider.net", "192.0.2.2"),
			},
		}
		assert.Equal(t, []string{"SURF-NS-003"}, delegationFindingIDs(t, d))
	})

	t.Run("different /24s are not", func(t *testing.T) {
		d := Delegation{
			Domain: "example.com",
			Nameservers: []Nameserver{
				healthy("ns1.provider.net", "192.0.2.1"),
				healthy("ns2.provider.net", "192.0.3.1"),
			},
		}
		assert.Empty(t, delegationFindingIDs(t, d))
	})

	// IPv6-only nameservers are not squeezed into a /24-shaped judgement,
	// because no IPv6 prefix means the same thing and the finding's reasoning
	// would not survive being read.
	t.Run("IPv6-only addresses are not assessed", func(t *testing.T) {
		d := Delegation{
			Domain: "example.com",
			Nameservers: []Nameserver{
				healthy("ns1.provider.net", "2001:db8::1"),
				healthy("ns2.provider.net", "2001:db8::2"),
			},
		}
		assert.Empty(t, delegationFindingIDs(t, d))
	})
}

func TestDelegationParentChildAgreement(t *testing.T) {
	base := Delegation{
		Domain: "example.com",
		Nameservers: []Nameserver{
			healthy("ns1.provider.net", "192.0.2.1"),
			healthy("ns2.provider.net", "198.51.100.1"),
		},
	}

	t.Run("disagreement is reported", func(t *testing.T) {
		d := base
		d.ParentNS = []string{"ns1.provider.net", "ns3.old.net"}
		d.ParentChecked = true
		assert.Equal(t, []string{"SURF-NS-004"}, delegationFindingIDs(t, d))
	})

	// Case and ordering are properties of the wire, not of the delegation.
	t.Run("case and order do not constitute disagreement", func(t *testing.T) {
		d := base
		d.ParentNS = []string{"NS2.Provider.NET.", "ns1.provider.net"}
		d.ParentChecked = true
		assert.Empty(t, delegationFindingIDs(t, d))
	})

	// An unreachable parent must produce silence, not a finding. Otherwise a
	// rate-limited TLD server would put a Medium on every domain under it.
	t.Run("an unconsulted parent yields nothing", func(t *testing.T) {
		d := base
		assert.Empty(t, delegationFindingIDs(t, d))
	})
}

func TestDelegationLame(t *testing.T) {
	t.Run("answered without AA is high confidence", func(t *testing.T) {
		lame := healthy("ns2.provider.net", "198.51.100.1")
		lame.Authoritative = false

		findings := DelegationHygiene(Origin{Target: "example.com"}, Delegation{
			Domain:      "example.com",
			Nameservers: []Nameserver{healthy("ns1.provider.net", "192.0.2.1"), lame},
		})

		require.Len(t, findings, 1)
		assert.Equal(t, "SURF-NS-005", findings[0].ID)
		assert.Equal(t, "high", findings[0].Confidence.String())
	})

	// Silence from one vantage point is weaker evidence than a reply without
	// the AA bit, and the finding must say so rather than assert a fault it
	// did not observe.
	t.Run("no response is reported at reduced confidence", func(t *testing.T) {
		silent := Nameserver{Host: "ns2.provider.net"}

		findings := DelegationHygiene(Origin{Target: "example.com"}, Delegation{
			Domain:      "example.com",
			Nameservers: []Nameserver{healthy("ns1.provider.net", "192.0.2.1"), silent},
		})

		require.Len(t, findings, 1)
		assert.Equal(t, "SURF-NS-005", findings[0].ID)
		assert.Equal(t, "medium", findings[0].Confidence.String())
	})
}

func TestDelegationGlue(t *testing.T) {
	nameservers := []Nameserver{
		healthy("ns1.example.com", "192.0.2.1"),
		healthy("ns2.example.com", "198.51.100.1"),
	}

	t.Run("missing glue is reported", func(t *testing.T) {
		d := Delegation{
			Domain: "example.com", Nameservers: nameservers,
			ParentNS:      []string{"ns1.example.com", "ns2.example.com"},
			ParentChecked: true,
			Glue:          map[string][]string{"ns1.example.com": {"192.0.2.1"}},
		}
		assert.Equal(t, []string{"SURF-NS-006"}, delegationFindingIDs(t, d))
	})

	// Out-of-bailiwick nameservers need no glue, and demanding it would report
	// the recommended configuration as a defect.
	t.Run("out-of-bailiwick nameservers need no glue", func(t *testing.T) {
		d := Delegation{
			Domain: "example.com",
			Nameservers: []Nameserver{
				healthy("ns1.provider.net", "192.0.2.1"),
				healthy("ns2.provider.net", "198.51.100.1"),
			},
			ParentNS:      []string{"ns1.provider.net", "ns2.provider.net"},
			ParentChecked: true,
		}
		assert.Empty(t, delegationFindingIDs(t, d))
	})
}

func TestDelegationOpenRecursion(t *testing.T) {
	open := healthy("ns2.provider.net", "198.51.100.1")
	open.OpenRecursive = true

	d := Delegation{
		Domain:      "example.com",
		Nameservers: []Nameserver{healthy("ns1.provider.net", "192.0.2.1"), open},
	}
	assert.Equal(t, []string{"SURF-NS-007"}, delegationFindingIDs(t, d))

	// A probe that never ran is not a clean result.
	untested := healthy("ns2.provider.net", "198.51.100.1")
	untested.RecursionTested = false
	untested.OpenRecursive = true
	d.Nameservers = []Nameserver{healthy("ns1.provider.net", "192.0.2.1"), untested}
	assert.Empty(t, delegationFindingIDs(t, d))
}

func TestDelegationSerialMismatch(t *testing.T) {
	stale := healthy("ns2.provider.net", "198.51.100.1")
	stale.Serial = 2026080201

	d := Delegation{
		Domain:      "example.com",
		Nameservers: []Nameserver{healthy("ns1.provider.net", "192.0.2.1"), stale},
	}
	assert.Equal(t, []string{"SURF-NS-008"}, delegationFindingIDs(t, d))

	// A server that returned no SOA has not disagreed about the serial; only
	// the servers that answered are compared.
	quiet := Nameserver{Host: "ns3.provider.net", Addresses: []string{"203.0.113.1"},
		Answered: true, Authoritative: true, RecursionTested: true}
	d.Nameservers = []Nameserver{healthy("ns1.provider.net", "192.0.2.1"), quiet}
	assert.Empty(t, delegationFindingIDs(t, d))
}

// A zone served by two independent providers has two unrelated serial
// schemes — one of them commonly a constant — so comparing across them would
// report the most resilient arrangement a domain can have as a fault.
func TestDelegationSerialsCompareWithinProviderOnly(t *testing.T) {
	route53 := healthy("ns-1283.awsdns-32.org", "192.0.2.1")
	route53.Provider, route53.Serial = "awsdns-32.org", 1
	nsone := healthy("dns1.p08.nsone.net", "198.51.100.1")
	nsone.Provider, nsone.Serial = "nsone.net", 1656468023

	d := Delegation{Domain: "example.com", Nameservers: []Nameserver{route53, nsone}}
	assert.Empty(t, delegationFindingIDs(t, d))

	// Within one provider a mismatch is still a replication problem.
	lagging := healthy("dns2.p08.nsone.net", "198.51.100.2")
	lagging.Provider, lagging.Serial = "nsone.net", 1656468022
	d.Nameservers = append(d.Nameservers, lagging)
	assert.Equal(t, []string{"SURF-NS-008"}, delegationFindingIDs(t, d))
}

func TestInBailiwick(t *testing.T) {
	assert.True(t, inBailiwick("example.com", "ns1.example.com"))
	assert.True(t, inBailiwick("example.com", "example.com"))
	assert.False(t, inBailiwick("example.com", "ns1.provider.net"))
	assert.False(t, inBailiwick("example.com", "ns1.notexample.com"))
}
