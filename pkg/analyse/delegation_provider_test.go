package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nsIDs(o Origin, d Delegation) []string {
	var ids []string
	for _, f := range DelegationHygiene(o, d) {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestSingleProviderReportsOneOperator(t *testing.T) {
	d := Delegation{
		Domain: "example.com",
		Nameservers: []Nameserver{
			{Host: "ns1.example-dns.net", Provider: "example-dns.net", Authoritative: true},
			{Host: "ns2.example-dns.net", Provider: "example-dns.net", Authoritative: true},
		},
	}
	assert.Contains(t, nsIDs(Origin{Target: "example.com"}, d), "DNSA-NS-002")
}

// Two independent operators is the arrangement the rule exists to encourage,
// so it must be silent there.
func TestSingleProviderIsQuietWithTwoOperators(t *testing.T) {
	d := Delegation{
		Domain: "example.com",
		Nameservers: []Nameserver{
			{Host: "ns1.example-dns.net", Provider: "example-dns.net", Authoritative: true},
			{Host: "ns1.other-dns.org", Provider: "other-dns.org", Authoritative: true},
		},
	}
	assert.NotContains(t, nsIDs(Origin{Target: "example.com"}, d), "DNSA-NS-002")
}

// A nameserver whose provider could not be determined may be the second
// operator. Concluding "all one provider" from an incomplete set would be a
// finding drawn from data that is missing.
func TestSingleProviderDeclinesOnIncompleteData(t *testing.T) {
	d := Delegation{
		Domain: "example.com",
		Nameservers: []Nameserver{
			{Host: "ns1.example-dns.net", Provider: "example-dns.net", Authoritative: true},
			{Host: "ns2.example-dns.net", Provider: "", Authoritative: true},
		},
	}
	assert.NotContains(t, nsIDs(Origin{Target: "example.com"}, d), "DNSA-NS-002")
}

// One nameserver is already fully described by DNSA-NS-001; adding a second
// finding for the same defect is noise.
func TestSingleProviderDefersToTheSingleNameserverRule(t *testing.T) {
	d := Delegation{
		Domain:      "example.com",
		Nameservers: []Nameserver{{Host: "ns1.example-dns.net", Provider: "example-dns.net", Authoritative: true}},
	}
	ids := nsIDs(Origin{Target: "example.com"}, d)
	assert.Contains(t, ids, "DNSA-NS-001")
	assert.NotContains(t, ids, "DNSA-NS-002")
}

// Vanity nameservers inside the zone say nothing about who operates them, so
// the observation stands but the confidence must not.
func TestSingleProviderDownConfidencesVanityNameservers(t *testing.T) {
	d := Delegation{
		Domain: "example.com",
		Nameservers: []Nameserver{
			{Host: "ns1.example.com", Provider: "example.com", Authoritative: true},
			{Host: "ns2.example.com", Provider: "example.com", Authoritative: true},
		},
	}

	var confidence string
	for _, got := range DelegationHygiene(Origin{Target: "example.com"}, d) {
		if got.ID == "DNSA-NS-002" {
			confidence = got.Confidence.String()
		}
	}
	require.Equal(t, "low", confidence)
}
