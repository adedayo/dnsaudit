package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ctIDs(obs CTObservation) []string {
	var ids []string
	for _, f := range CertificateTransparency(Origin{Target: obs.Domain}, obs) {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestCTReportsCertificateForAVanishedHost(t *testing.T) {
	obs := CTObservation{
		Domain: "example.com",
		Source: "crt.sh",
		Hosts: []CTHost{{
			Host: "old.example.com", NXDOMAIN: true,
			Issuer: "CN=Test CA", Expiry: "2026-12-01",
		}},
	}
	assert.Equal(t, []string{"DNSA-CT-001"}, ctIDs(obs))
}

// A name that still resolves is simply in service.
func TestCTIsQuietForLiveHosts(t *testing.T) {
	obs := CTObservation{
		Domain: "example.com",
		Hosts:  []CTHost{{Host: "www.example.com", Resolves: true}},
	}
	assert.Empty(t, ctIDs(obs))
}

// The defect family this project has met most often: a query that failed read
// as a definitive answer. Neither resolving nor NXDOMAIN means nothing was
// established, and nothing may be reported.
func TestCTIsSilentWhenResolutionEstablishedNothing(t *testing.T) {
	obs := CTObservation{
		Domain: "example.com",
		Hosts:  []CTHost{{Host: "old.example.com", Resolves: false, NXDOMAIN: false}},
	}
	assert.Empty(t, ctIDs(obs))
}

func TestCTReportsInternalLookingNames(t *testing.T) {
	for _, host := range []string{
		"vpn.example.com", "jira.example.com", "staging.example.com",
		"uat2.example.com", "internal.corp.example.com", "grafana.example.com",
	} {
		obs := CTObservation{
			Domain: "example.com",
			Hosts:  []CTHost{{Host: host, Resolves: true}},
		}
		assert.Contains(t, ctIDs(obs), "DNSA-CT-002", host)
	}
}

// The rule must be reported at medium confidence: a keyword suggests, it does
// not establish. "test.example.com" may be a production service.
func TestCTInternalNameIsMediumConfidence(t *testing.T) {
	obs := CTObservation{
		Domain: "example.com",
		Hosts:  []CTHost{{Host: "staging.example.com", Resolves: true}},
	}

	findings := CertificateTransparency(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 1)
	assert.Equal(t, "medium", findings[0].Confidence.String())
}

// Substring matching would make this rule fire on ordinary public names often
// enough that readers would learn to skip it.
func TestCTInternalKeywordsMatchWholeLabelsOnly(t *testing.T) {
	for _, host := range []string{
		"developer.example.com", // contains "dev"
		"contest.example.com",   // contains "test"
		"corporate.example.com", // contains "corp"
		"admin-guide.example.com",
	} {
		obs := CTObservation{
			Domain: "example.com",
			Hosts:  []CTHost{{Host: host, Resolves: true}},
		}
		assert.NotContains(t, ctIDs(obs), "DNSA-CT-002", host)
	}
}

// An organisation called Test Ltd is not leaking an internal hostname by owning
// test.com, so the registrable domain itself is never the evidence.
func TestCTIgnoresKeywordsInTheRegistrableDomain(t *testing.T) {
	obs := CTObservation{
		Domain: "test.com",
		Hosts:  []CTHost{{Host: "test.com", Resolves: true}},
	}
	assert.NotContains(t, ctIDs(obs), "DNSA-CT-002")
}

func TestCTReportsWildcardCoveringTheApex(t *testing.T) {
	obs := CTObservation{
		Domain:        "example.com",
		WildcardNames: []string{"*.example.com"},
	}
	assert.Equal(t, []string{"DNSA-CT-003"}, ctIDs(obs))
}

// A wildcard deeper in the tree covers a subtree, not the apex, and the rule
// says apex.
func TestCTIgnoresWildcardsBelowTheApex(t *testing.T) {
	obs := CTObservation{
		Domain:        "example.com",
		WildcardNames: []string{"*.dev.example.com"},
	}
	assert.Empty(t, ctIDs(obs))
}

func TestCTRecordsShowTheInventory(t *testing.T) {
	obs := CTObservation{
		Domain: "example.com", Source: "crt.sh", CertificateCount: 42,
		Hosts: []CTHost{
			{Host: "www.example.com", Resolves: true},
			{Host: "old.example.com", NXDOMAIN: true},
			{Host: "unknown.example.com"},
		},
	}

	records := CTRecords(obs)
	require.Len(t, records, 5)
	assert.Contains(t, records[0], "42 certificates examined via crt.sh")
	assert.Contains(t, records[2], "(resolves)")
	assert.Contains(t, records[3], "(NXDOMAIN)")
	// A reader must be able to tell a name that is gone from one nobody could
	// ask about.
	assert.Contains(t, records[4], "unknown")
}

func TestCTHostNamesFeedTheOtherChecks(t *testing.T) {
	obs := CTObservation{Hosts: []CTHost{
		{Host: "www.example.com"}, {Host: "api.example.com"},
	}}
	assert.Equal(t, []string{"www.example.com", "api.example.com"}, CTHostNames(obs))
}
