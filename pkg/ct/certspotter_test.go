package ct

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubSource is a Source with a fixed outcome, for exercising the fallback.
type stubSource struct {
	name  string
	certs []Certificate
	err   error
	calls *int
}

func (s stubSource) Name() string { return s.name }

func (s stubSource) Search(context.Context, string) ([]Certificate, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.certs, s.err
}

func TestSourcesUsesTheFirstSourceThatAnswers(t *testing.T) {
	var secondCalls int
	sources := Sources{
		stubSource{name: "first", certs: []Certificate{{Names: []string{"a.example.com"}}}},
		stubSource{name: "second", calls: &secondCalls},
	}

	certs, err := sources.Search(context.Background(), "example.com")

	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, []string{"a.example.com"}, certs[0].Names)
	// A source that is never needed must never be queried: each call is
	// traffic to somebody else's free service.
	assert.Zero(t, secondCalls, "the second source should not be queried once the first answers")
}

func TestSourcesFallsBackWhenTheFirstSourceFails(t *testing.T) {
	sources := Sources{
		stubSource{name: "first", err: errors.New("error: HTTP 502")},
		stubSource{name: "second", certs: []Certificate{{Names: []string{"b.example.com"}}}},
	}

	certs, err := sources.Search(context.Background(), "example.com")

	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, []string{"b.example.com"}, certs[0].Names)
}

func TestSourcesReportsEveryFailureWhenNoneAnswer(t *testing.T) {
	sources := Sources{
		stubSource{name: "first", err: errors.New("error: HTTP 502")},
		stubSource{name: "second", err: errors.New("error: rate limit reached")},
	}

	_, err := sources.Search(context.Background(), "example.com")

	require.Error(t, err)
	// Naming only the last service tried would send the reader to investigate
	// the wrong one.
	assert.Contains(t, err.Error(), "first: HTTP 502")
	assert.Contains(t, err.Error(), "second: rate limit reached")
}

func TestSourcesNameListsEverySourceTried(t *testing.T) {
	sources := Sources{stubSource{name: "certspotter"}, stubSource{name: "crt.sh"}}
	assert.Equal(t, "certspotter or crt.sh", sources.Name())
}

func TestCertSpotterParsesIssuancesAndRequestsSubdomains(t *testing.T) {
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{
				"dns_names": ["example.com", "WWW.Example.com."],
				"issuer": {"friendly_name": "Let's Encrypt", "name": "C=US, O=Let's Encrypt"},
				"not_before": "2026-01-02T03:04:05Z",
				"not_after": "2026-04-02T03:04:05Z"
			}
		]`))
	}))
	defer server.Close()

	certs, err := certSpotter{BaseURL: server.URL}.Search(context.Background(), "example.com")

	require.NoError(t, err)
	require.Len(t, certs, 1)
	// Names are normalised at the source so every downstream comparison is
	// against one form.
	assert.Equal(t, []string{"example.com", "www.example.com"}, certs[0].Names)
	assert.Equal(t, "Let's Encrypt", certs[0].Issuer)
	assert.Equal(t, 2026, certs[0].NotAfter.Year())

	// Without include_subdomains the API returns only the apex, which would
	// make the whole check pointless.
	assert.Equal(t, "true", gotQuery.Get("include_subdomains"))
	assert.Equal(t, "example.com", gotQuery.Get("domain"))
	assert.ElementsMatch(t, []string{"dns_names", "issuer"}, gotQuery["expand"])
}

func TestCertSpotterFallsBackToTheFullIssuerName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"dns_names":["a.example.com"],
			"issuer":{"name":"C=US, O=Some CA"}}]`))
	}))
	defer server.Close()

	certs, err := certSpotter{BaseURL: server.URL}.Search(context.Background(), "example.com")

	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "C=US, O=Some CA", certs[0].Issuer)
}

func TestCertSpotterExplainsARateLimitRatherThanTheStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	_, err := certSpotter{BaseURL: server.URL}.Search(context.Background(), "example.com")

	require.Error(t, err)
	// The remedy is to wait, not to investigate the domain, so the message has
	// to say that.
	assert.Contains(t, strings.ToLower(err.Error()), "rate limit")
	assert.Contains(t, err.Error(), "retry later")
}

func TestCertSpotterReportsAnUnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	_, err := certSpotter{BaseURL: server.URL}.Search(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestCertSpotterRejectsAnUnparseableBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer server.Close()

	_, err := certSpotter{BaseURL: server.URL}.Search(context.Background(), "example.com")

	require.Error(t, err)
	// An unreadable answer must not be mistaken for a domain with no
	// certificates, which is what returning no error would mean.
	assert.Contains(t, err.Error(), "cannot parse")
}

func TestCertSpotterDiscardsIssuancesWithNoUsableNames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"dns_names":["", "  "],"issuer":{"name":"CA"}}]`))
	}))
	defer server.Close()

	certs, err := certSpotter{BaseURL: server.URL}.Search(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Empty(t, certs)
}

func TestParseTimestampReadsBothAPIFormats(t *testing.T) {
	// crt.sh omits the zone; Cert Spotter sends RFC 3339.
	assert.Equal(t, 2026, parseTimestamp("2026-01-02T03:04:05").Year())
	assert.Equal(t, 2026, parseTimestamp("2026-01-02T03:04:05Z").Year())
	// An unreadable timestamp yields the zero time rather than a wrong one.
	assert.True(t, parseTimestamp("yesterday").IsZero())
}
