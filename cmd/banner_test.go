package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The help preamble is the first thing a new user reads, so it has to say what
// the tool is for, which build they are running and who wrote it.
func TestBannerCarriesPurposeVersionAndAuthor(t *testing.T) {
	b := banner()

	assert.Contains(t, b, "external attack surface posture")
	assert.Contains(t, b, "Version: ")
	assert.Contains(t, b, "Author: Dr. Adedayo Adetoye (Dayo) <https://github.com/adedayo>")
}

// The version in the banner must be the running build's, not a constant that
// can drift: someone quoting the help output is telling us which binary they
// have.
func TestBannerVersionMatchesTheBuild(t *testing.T) {
	v, _, _ := buildInfo()
	require.NotEmpty(t, v)
	assert.Contains(t, banner(), "Version: "+v)
}

// The banner has to reach the help output, not merely exist.
func TestRootHelpBeginsWithTheBanner(t *testing.T) {
	rootCmd.Long = banner() + "\n\ndetails"

	help := rootCmd.Long
	assert.True(t, strings.HasPrefix(help, "See what an attacker sees"),
		"the banner must come first, before the detailed description")
}
