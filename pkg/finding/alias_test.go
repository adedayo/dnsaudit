package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/finding"
)

// The rename from dnsaudit to vantage re-prefixed every rule from DNSA- to
// SURF-, which broke the identifier stability the README promises. These tests
// pin the migration path that makes that survivable.

func TestLookupAcceptsLegacyIdentifier(t *testing.T) {
	legacy, ok := finding.Lookup("DNSA-SPF-004")
	require.True(t, ok, "a baseline written against DNSA-SPF-004 must keep resolving")

	current, ok := finding.Lookup("SURF-SPF-004")
	require.True(t, ok)

	assert.Equal(t, current, legacy, "the alias must resolve to the same rule")
	assert.Equal(t, "SURF-SPF-004", legacy.ID,
		"the entry returned always reports its canonical ID")
}

func TestCanonicalIDRewritesLegacyPrefix(t *testing.T) {
	assert.Equal(t, "SURF-SPF-004", finding.CanonicalID("DNSA-SPF-004"))
}

func TestCanonicalIDLeavesCurrentIdentifiersAlone(t *testing.T) {
	assert.Equal(t, "SURF-SPF-004", finding.CanonicalID("SURF-SPF-004"))
}

func TestCanonicalIDLeavesUnknownIdentifiersAlone(t *testing.T) {
	// Echoing back what the caller supplied keeps the "unknown rule" message
	// about their input rather than about a string they never typed.
	assert.Equal(t, "DNSA-NOPE-999", finding.CanonicalID("DNSA-NOPE-999"))
	assert.Equal(t, "nonsense", finding.CanonicalID("nonsense"))
}

func TestEveryCurrentIdentifierHasALegacyAlias(t *testing.T) {
	// Every rule that existed under the old prefix must still be reachable by
	// it, otherwise the migration is only partial and silently so.
	for _, e := range finding.Catalogue() {
		legacy := "DNSA-" + e.ID[len("SURF-"):]
		got, ok := finding.Lookup(legacy)
		require.Truef(t, ok, "no legacy alias for %s", e.ID)
		assert.Equal(t, e.ID, got.ID)
	}
}
