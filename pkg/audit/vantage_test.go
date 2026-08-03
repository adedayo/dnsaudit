package audit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/audit"
)

func TestParseVantageAcceptsExternal(t *testing.T) {
	v, err := audit.ParseVantage("external")
	require.NoError(t, err)
	assert.Equal(t, audit.VantageExternal, v)
}

func TestDefaultVantageIsExternal(t *testing.T) {
	// The default must be the vantage that is actually implemented, so that
	// running the tool with no flags never produces a usage error.
	_, err := audit.ParseVantage(string(audit.DefaultVantage))
	assert.NoError(t, err)
}

func TestParseVantageRejectsInternalAsUnimplemented(t *testing.T) {
	// A recognised-but-absent capability must not be reported as a typo.
	_, err := audit.ParseVantage("internal")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented yet")
	assert.NotContains(t, err.Error(), "unknown vantage")
}

func TestParseVantageRejectsUnknown(t *testing.T) {
	_, err := audit.ParseVantage("sideways")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown vantage")
}

func TestVantagesOnlyAdvertisesImplementedValues(t *testing.T) {
	// Help text is a promise. Anything listed here must parse.
	for _, name := range audit.Vantages() {
		_, err := audit.ParseVantage(name)
		assert.NoErrorf(t, err, "advertised vantage %q must be usable", name)
	}
}
