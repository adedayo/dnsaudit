package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxIDs(hosts []MXHost) []string {
	var ids []string
	for _, f := range MX(Origin{Target: "example.com"}, hosts, true) {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestMXSingleProviderReportsOneOperator(t *testing.T) {
	hosts := []MXHost{
		{Preference: 10, Host: "alt1.aspmx.l.google.com", Resolves: true, Provider: "google.com"},
		{Preference: 20, Host: "alt2.aspmx.l.google.com", Resolves: true, Provider: "google.com"},
	}
	assert.Contains(t, mxIDs(hosts), "DNSA-MX-005")
}

// Two operators is the arrangement the rule exists to encourage.
func TestMXSingleProviderIsQuietWithTwoOperators(t *testing.T) {
	hosts := []MXHost{
		{Preference: 10, Host: "mx.example-mail.com", Resolves: true, Provider: "example-mail.com"},
		{Preference: 20, Host: "backup.other-mail.net", Resolves: true, Provider: "other-mail.net"},
	}
	assert.NotContains(t, mxIDs(hosts), "DNSA-MX-005")
}

// DNSA-MX-004 already describes the single-exchanger case in full.
func TestMXSingleProviderDefersToTheSingleExchangerRule(t *testing.T) {
	hosts := []MXHost{{Preference: 10, Host: "mx.example-mail.com", Resolves: true, Provider: "example-mail.com"}}
	ids := mxIDs(hosts)
	assert.Contains(t, ids, "DNSA-MX-004")
	assert.NotContains(t, ids, "DNSA-MX-005")
}

// An exchanger whose provider could not be established may be the second
// operator, so nothing may be concluded about the set.
func TestMXSingleProviderDeclinesOnIncompleteData(t *testing.T) {
	hosts := []MXHost{
		{Preference: 10, Host: "mx.example-mail.com", Resolves: true, Provider: "example-mail.com"},
		{Preference: 20, Host: "localhost", Resolves: true, Provider: ""},
	}
	assert.NotContains(t, mxIDs(hosts), "DNSA-MX-005")
}

// A null MX is a complete policy statement: the domain accepts no mail, so
// there is no mail path to have a provider.
func TestMXSingleProviderIgnoresNullMX(t *testing.T) {
	assert.Empty(t, mxIDs([]MXHost{{Preference: 0, Host: "."}}))
}

// Exchangers named inside the organisation's own domain say nothing about who
// runs them, so the observation stands but the confidence must not.
func TestMXSingleProviderDownConfidencesSelfNamedExchangers(t *testing.T) {
	hosts := []MXHost{
		{Preference: 10, Host: "mail.example.com", Resolves: true, Provider: "example.com"},
		{Preference: 20, Host: "mail2.example.com", Resolves: true, Provider: "example.com"},
	}

	var confidence string
	for _, f := range MX(Origin{Target: "example.com"}, hosts, true) {
		if f.ID == "DNSA-MX-005" {
			confidence = f.Confidence.String()
		}
	}
	require.Equal(t, "low", confidence)
}
