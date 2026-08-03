//go:build live

// The live tests verify that fallback endpoints are parseable against the real
// services rather than only against fixtures. They are excluded from normal
// runs because they require network access:
//
//	go test -tags live ./pkg/netattr/
package netattr

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestLiveCloudflareFallbackParsesTheRealAPI guards against the fallback being
// correct only against a fixture. A fallback that has never been parsed from
// the live endpoint is an assumption, not a resilience measure.
//
// An unreachable endpoint skips: that is the service's problem or the
// network's, and failing here would only punish whoever ran the tests. A
// reachable endpoint whose shape we can no longer parse fails, because that is
// precisely the regression this test exists to catch.
func TestLiveCloudflareFallbackParsesTheRealAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.cloudflare.com/client/v4/ips", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("Cloudflare API unreachable, cannot verify the fallback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("Cloudflare API returned %s, cannot verify the fallback", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err, "reading a response the server already accepted should not fail")

	v4, err := parseCloudflareAPIv4(body)
	require.NoError(t, err, "the live Cloudflare API is no longer parseable by the fallback")
	require.NotEmpty(t, v4, "the fallback parsed the live API but found no IPv4 prefixes")

	v6, err := parseCloudflareAPIv6(body)
	require.NoError(t, err, "the live Cloudflare API is no longer parseable by the fallback")
	require.NotEmpty(t, v6, "the fallback parsed the live API but found no IPv6 prefixes")

	t.Logf("live Cloudflare API: %d IPv4 prefixes, %d IPv6 prefixes", len(v4), len(v6))
}
