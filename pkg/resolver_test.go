package vantage

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormaliseServer(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "1.1.1.1", want: "1.1.1.1:53"},
		{in: " 8.8.8.8 ", want: "8.8.8.8:53"},
		{in: "8.8.8.8:5353", want: "8.8.8.8:5353"},
		{in: "2606:4700:4700::1111", want: "[2606:4700:4700::1111]:53"},
		{in: "[2606:4700:4700::1111]", want: "[2606:4700:4700::1111]:53"},
		{in: "[2606:4700:4700::1111]:53", want: "[2606:4700:4700::1111]:53"},
		{in: "resolver.example.com", want: "resolver.example.com:53"},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
	}
	for _, c := range cases {
		got, err := normaliseServer(c.in)
		if c.wantErr {
			assert.Error(t, err, "input %q", c.in)
			continue
		}
		require.NoError(t, err, "input %q", c.in)
		assert.Equal(t, c.want, got, "input %q", c.in)
	}
}

func TestNormaliseServersDeduplicatesAndDropsInvalid(t *testing.T) {
	got := normaliseServers([]string{"1.1.1.1", "1.1.1.1:53", "", "8.8.8.8"})
	assert.Equal(t, []string{"1.1.1.1:53", "8.8.8.8:53"}, got)
}

func TestSetResolversOverridesDiscovery(t *testing.T) {
	t.Cleanup(func() { SetResolvers() })

	SetResolvers("192.0.2.1", "192.0.2.2:5353")
	assert.Equal(t, []string{"192.0.2.1:53", "192.0.2.2:5353"}, Resolvers())

	// Clearing the override restores auto-discovery.
	SetResolvers()
	assert.NotEmpty(t, Resolvers())
}

func TestResolversFromEnvironment(t *testing.T) {
	t.Cleanup(func() {
		SetResolvers()
		ResetResolverCache()
	})

	t.Setenv(ResolverEnvVar, "192.0.2.10, 192.0.2.11:5353")
	SetResolvers() // ensure no override is in effect
	ResetResolverCache()

	assert.Equal(t, []string{"192.0.2.10:53", "192.0.2.11:5353"}, Resolvers())
}

// TestResolversAlwaysAvailable is the platform-independence guarantee: whatever
// the operating system (Linux, macOS, Windows) and however it is configured,
// callers always receive at least one usable resolver address.
func TestResolversAlwaysAvailable(t *testing.T) {
	t.Cleanup(func() {
		SetResolvers()
		ResetResolverCache()
	})

	require.NoError(t, os.Unsetenv(ResolverEnvVar))
	SetResolvers()
	ResetResolverCache()

	servers := Resolvers()
	require.NotEmpty(t, servers)
	for _, s := range servers {
		normalised, err := normaliseServer(s)
		require.NoError(t, err)
		assert.Equal(t, s, normalised, "resolver %q should already be normalised", s)
	}
}

func TestFallbackResolversAreWellFormed(t *testing.T) {
	for _, s := range FallbackResolvers {
		normalised, err := normaliseServer(s)
		require.NoError(t, err, "fallback %q", s)
		assert.Equal(t, s, normalised, "fallback %q should be in host:port form", s)
	}
}
