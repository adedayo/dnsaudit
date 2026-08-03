package ct

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrtShParsesTheResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "%.example.com", r.URL.Query().Get("q"))
		assert.Equal(t, "json", r.URL.Query().Get("output"))
		_, _ = w.Write([]byte(`[
			{"name_value":"www.example.com\nexample.com","issuer_name":"C=US, O=Let's Encrypt, CN=R3",
			 "not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00"},
			{"name_value":"*.example.com","issuer_name":"CN=Test CA",
			 "not_before":"2026-02-01T00:00:00","not_after":"2026-05-01T00:00:00"}
		]`))
	}))
	defer srv.Close()

	certs, err := crtSh{BaseURL: srv.URL + "/"}.Search(context.Background(), "example.com")
	require.NoError(t, err)
	require.Len(t, certs, 2)

	// Subject alternative names arrive newline-separated in a single field and
	// must be split, or every certificate would look like one absurd hostname.
	assert.ElementsMatch(t, []string{"www.example.com", "example.com"}, certs[0].Names)
	assert.Equal(t, 2026, certs[0].NotAfter.Year())
}

// A log service returning an error must not be reported as "this domain has no
// certificates", which is what an empty result would mean.
func TestCrtShReportsAnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := crtSh{BaseURL: srv.URL + "/"}.Search(context.Background(), "example.com")
	assert.Error(t, err)
}

// Certificates routinely cover several unrelated domains — a shared hosting
// certificate may list hundreds — so a name that merely appeared alongside the
// target is not the target's. Assessing those would mean reporting on somebody
// else's infrastructure.
func TestCollectDiscardsNamesOutsideTheDomain(t *testing.T) {
	certs := []Certificate{{Names: []string{
		"www.example.com",
		"api.example.com",
		"unrelated.example.org",
		"notexample.com",
		"example.com.attacker.net",
	}}}

	result := Collect("example.com", certs)
	assert.Equal(t, []string{"api.example.com", "www.example.com"}, result.Hosts)
}

// A wildcard identity names no host, so it must not join the set of names to
// resolve — every one of them would be NXDOMAIN and reported as abandoned.
func TestCollectSeparatesWildcards(t *testing.T) {
	certs := []Certificate{{Names: []string{"*.example.com", "www.example.com"}}}

	result := Collect("example.com", certs)
	assert.Equal(t, []string{"www.example.com"}, result.Hosts)
	assert.Equal(t, []string{"*.example.com"}, result.WildcardNames)
}

// The same name arriving in different cases, or with a trailing dot, is one
// name. Collect normalises rather than trusting the source, so a second Source
// implementation cannot introduce duplicates that all get resolved separately.
func TestCollectDeduplicatesAndSorts(t *testing.T) {
	certs := []Certificate{
		{Names: []string{"www.example.com", "api.example.com"}},
		{Names: []string{"WWW.example.com.", "api.example.com"}},
	}

	result := Collect("example.com", certs)
	assert.Equal(t, []string{"api.example.com", "www.example.com"}, result.Hosts)
}

// The cache filename is built from the domain, so a name containing a path
// separator must not be able to write outside the cache directory.
func TestSanitiseNeutralisesPathTraversal(t *testing.T) {
	assert.NotContains(t, sanitise("../../etc/passwd"), "/")
	assert.NotContains(t, sanitise("..\\..\\windows"), "\\")
	assert.NotEqual(t, "..", sanitise(".."))
	assert.NotEqual(t, ".", sanitise("."))
}
