package netattr

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withSources substitutes the published range list for the duration of a test.
func withSources(t *testing.T, sources ...struct {
	name  string
	url   string
	parse func([]byte) ([]ProviderRange, error)
}) {
	t.Helper()
	original := providerSources
	providerSources = sources
	Reset()
	t.Cleanup(func() {
		providerSources = original
		Reset()
	})
}

// source builds one entry of the published range list.
func source(name, url string, parse func([]byte) ([]ProviderRange, error)) struct {
	name  string
	url   string
	parse func([]byte) ([]ProviderRange, error)
} {
	return struct {
		name  string
		url   string
		parse func([]byte) ([]ProviderRange, error)
	}{name, url, parse}
}

func TestLoadCollectsRangesAndReportsCompleteCoverage(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("52.0.0.0/8\n"))
	}))
	defer server.Close()

	withSources(t, source("Example Cloud", server.URL, parsePlainList))

	set, err := Load(context.Background())
	require.NoError(t, err)

	assert.True(t, set.Complete())
	assert.Empty(t, set.Stale)
	require.Len(t, set.Providers, 1)
	assert.Equal(t, "Example Cloud", set.Providers[0].Name)

	got := set.Lookup(netip.MustParseAddr("52.1.2.3"))
	assert.Equal(t, "Example Cloud", got.Provider)
}

// The dangerous case: one source fails and the rest succeed. Load returns no
// error, so without Failed the run would continue with a silent coverage hole
// and DNSA-NET-001 would stop firing for that operator.
func TestLoadReportsPartialFailureWithoutFailingTheRun(t *testing.T) {
	isolateCache(t)

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer good.Close()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	withSources(t,
		source("Good Cloud", good.URL, parsePlainList),
		source("Broken Cloud", bad.URL, parsePlainList),
	)

	set, err := Load(context.Background())
	require.NoError(t, err, "one failed source must not fail the whole load")

	assert.False(t, set.Complete())
	require.Len(t, set.Failed, 1)
	assert.Contains(t, set.Failed[0], "Broken Cloud")
	assert.Len(t, set.Providers, 1)
}

// A parse failure is a coverage gap exactly as a fetch failure is: the operator
// changed their format and this tool no longer understands it.
func TestLoadTreatsAnUnparseableSourceAsAFailure(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"unexpected": "shape"}`))
	}))
	defer server.Close()

	withSources(t, source("Reshaped Cloud", server.URL, func([]byte) ([]ProviderRange, error) {
		return nil, fmt.Errorf("unrecognised format")
	}))

	_, err := Load(context.Background())
	require.Error(t, err, "no usable provider means the check cannot proceed")
	assert.Contains(t, err.Error(), "Reshaped Cloud")
	assert.Contains(t, err.Error(), "unrecognised format")
}

func TestLoadFailsWhenEverySourceIsUnavailable(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	withSources(t, source("Example Cloud", url, parsePlainList))

	_, err := Load(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no cloud provider ranges could be retrieved")
}

// Serving week-old data is defensible; doing so without saying is not.
func TestLoadReportsStaleDataWhenTheSourceCannotBeRefreshed(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	url := server.URL
	withSources(t, source("Example Cloud", url, parsePlainList))

	// Populate the cache, age it beyond the TTL, then take the source away.
	_, err := Load(context.Background())
	require.NoError(t, err)

	path, err := cachePath(url)
	require.NoError(t, err)
	old := time.Now().Add(-CacheTTL - 48*time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))
	server.Close()
	Reset()

	set, err := Load(context.Background())
	require.NoError(t, err)

	// Coverage is not incomplete — the data is usable — but it was not
	// refreshed, and a reader comparing two runs deserves to know.
	assert.True(t, set.Complete())
	require.Len(t, set.Stale, 1)
	assert.Contains(t, set.Stale[0], "Example Cloud")
	assert.Contains(t, set.Stale[0], "cached")
	assert.Len(t, set.Providers, 1)
}

// Auditing a portfolio must pay for the download once, not once per domain.
func TestLoadMemoisesForTheProcess(t *testing.T) {
	isolateCache(t)

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	withSources(t, source("Example Cloud", server.URL, parsePlainList))

	for range 3 {
		_, err := Load(context.Background())
		require.NoError(t, err)
	}
	assert.Equal(t, 1, requests)
}

// Two publications for one operator, as Cloudflare's separate v4 and v6 lists
// are, must merge rather than appear as two providers.
func TestLoadMergesSourcesSharingAProviderName(t *testing.T) {
	isolateCache(t)

	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("52.0.0.0/8\n"))
	}))
	defer v4.Close()
	v6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2606:4700::/32\n"))
	}))
	defer v6.Close()

	withSources(t,
		source("Example Cloud", v4.URL, parsePlainList),
		source("Example Cloud", v6.URL, parsePlainList),
	)

	set, err := Load(context.Background())
	require.NoError(t, err)

	require.Len(t, set.Providers, 1, "one operator must not appear twice")
	assert.Equal(t, "Example Cloud", set.Lookup(netip.MustParseAddr("52.1.2.3")).Provider)
	assert.Equal(t, "Example Cloud", set.Lookup(netip.MustParseAddr("2606:4700::1")).Provider)
}

// Special-purpose space short-circuits attribution: an operator cannot announce
// RFC 1918 or documentation space, and a provider file claiming otherwise must
// not override the registry.
func TestLookupPrefersSpecialPurposeSpaceOverAProviderClaim(t *testing.T) {
	isolateCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	withSources(t, source("Confused Cloud", server.URL, parsePlainList))

	set, err := Load(context.Background())
	require.NoError(t, err)

	got := set.Lookup(netip.MustParseAddr("203.0.113.9"))
	require.NotNil(t, got.Special)
	assert.Empty(t, got.Provider)
}
