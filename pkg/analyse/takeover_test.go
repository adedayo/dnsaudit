package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/takeover"
)

func takeoverIDs(t *testing.T, obs TakeoverObservation) []string {
	t.Helper()
	var ids []string
	for _, f := range Takeover(Origin{Target: obs.Domain}, obs) {
		ids = append(ids, f.ID)
	}
	return ids
}

// nxdomainService is a service where a dangling name leaves the target
// unresolvable, so DNS alone settles the question.
var nxdomainService = takeover.Fingerprint{
	Service: "AWS S3", NXDOMAIN: true, Status: takeover.StatusVulnerable,
	Reference: "https://example.invalid/s3",
}

// httpOnlyService is a service whose target always resolves, so only an HTTP
// response can distinguish a claimed name from an abandoned one.
var httpOnlyService = takeover.Fingerprint{
	Service: "GitHub Pages", NXDOMAIN: false, Status: takeover.StatusVulnerable,
	HTTPBody:  []string{"There isn't a GitHub Pages site here."},
	Reference: "https://example.invalid/pages",
}

func TestTakeoverKnownServiceNXDOMAIN(t *testing.T) {
	obs := TakeoverObservation{
		Domain: "example.com",
		Hosts: []TakeoverHost{{
			Host: "assets.example.com", CNAME: "old.s3.amazonaws.com",
			Chain:          []string{"old.s3.amazonaws.com"},
			TargetNXDOMAIN: true, Fingerprint: &nxdomainService,
		}},
	}
	assert.Equal(t, []string{"SURF-TKO-001"}, takeoverIDs(t, obs))
}

func TestTakeoverUnknownServiceNXDOMAIN(t *testing.T) {
	obs := TakeoverObservation{
		Domain: "example.com",
		Hosts: []TakeoverHost{{
			Host: "legacy.example.com", CNAME: "gone.provider.invalid",
			Chain: []string{"gone.provider.invalid"}, TargetNXDOMAIN: true,
		}},
	}
	assert.Equal(t, []string{"SURF-TKO-004"}, takeoverIDs(t, obs))
}

// The single most important negative case: a query that failed is not an
// NXDOMAIN. A Critical takeover finding raised because a resolver timed out
// would be the worst false positive this tool could produce.
func TestTakeoverUnknownTargetStateIsNotAFinding(t *testing.T) {
	obs := TakeoverObservation{
		Domain: "example.com",
		Hosts: []TakeoverHost{{
			Host: "assets.example.com", CNAME: "old.s3.amazonaws.com",
			Chain: []string{"old.s3.amazonaws.com"},
			// Neither resolved nor NXDOMAIN: SERVFAIL, a timeout, or an empty
			// NOERROR. Nothing was established.
			TargetResolves: false, TargetNXDOMAIN: false,
			Fingerprint: &nxdomainService,
		}},
	}
	assert.Empty(t, takeoverIDs(t, obs))
}

// A live alias to a service in normal use must be silent, otherwise the check
// would fire on every correctly configured S3 or Azure hostname in existence.
func TestTakeoverLiveAliasIsSilent(t *testing.T) {
	obs := TakeoverObservation{
		Domain: "example.com",
		Hosts: []TakeoverHost{{
			Host: "assets.example.com", CNAME: "live.s3.amazonaws.com",
			Chain:          []string{"live.s3.amazonaws.com"},
			TargetResolves: true, Fingerprint: &nxdomainService,
		}},
	}
	assert.Empty(t, takeoverIDs(t, obs))
}

func TestTakeoverUnverifiableService(t *testing.T) {
	obs := TakeoverObservation{
		Domain: "example.com",
		Hosts: []TakeoverHost{{
			Host: "docs.example.com", CNAME: "example.github.io",
			Chain:          []string{"example.github.io"},
			TargetResolves: true, Fingerprint: &httpOnlyService,
		}},
	}

	findings := Takeover(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 1)
	assert.Equal(t, "SURF-TKO-003", findings[0].ID)
	// The rule states an ambiguity, not a defect, so it must not carry the
	// confidence of an observation.
	assert.Equal(t, "low", findings[0].Confidence.String())

	// Once corroboration has run and found the name in use, saying otherwise
	// would be worse than never having looked.
	obs.HTTPCorroborated = true
	obs.Hosts[0].HTTPFetched = true
	assert.Empty(t, takeoverIDs(t, obs))
}

// Corroboration being enabled is not the same as corroboration having
// succeeded. When the request failed nothing was established, so the
// unverified finding must survive: suppressing it would report a name as in
// use on the strength of a question that was never answered.
func TestTakeoverCorroborationFailureDoesNotSuppress(t *testing.T) {
	obs := TakeoverObservation{
		Domain:           "example.com",
		HTTPCorroborated: true,
		Hosts: []TakeoverHost{{
			Host: "docs.example.com", CNAME: "example.github.io",
			Chain:          []string{"example.github.io"},
			TargetResolves: true, Fingerprint: &httpOnlyService,
			HTTPFetched: false,
		}},
	}
	assert.Equal(t, []string{"SURF-TKO-003"}, takeoverIDs(t, obs))
}

// The service's own error page saying the name is unregistered is stronger
// evidence than any DNS answer, and is reported as such even though the alias
// target still resolves.
func TestTakeoverHTTPCorroborationConfirms(t *testing.T) {
	obs := TakeoverObservation{
		Domain:           "example.com",
		HTTPCorroborated: true,
		Hosts: []TakeoverHost{{
			Host: "docs.example.com", CNAME: "example.github.io",
			Chain:          []string{"example.github.io"},
			TargetResolves: true, Fingerprint: &httpOnlyService,
			HTTPFetched: true, HTTPUnclaimed: true,
			HTTPMatched: "There isn't a GitHub Pages site here.",
			HTTPURL:     "https://docs.example.com/",
		}},
	}

	findings := Takeover(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 1)
	assert.Equal(t, "SURF-TKO-002", findings[0].ID)
	assert.Equal(t, "high", findings[0].Confidence.String())

	// The matched fragment is carried as evidence, so a reader can see what
	// the Critical verdict rests on rather than taking it on trust.
	var fragments []string
	for _, e := range findings[0].Evidence {
		fragments = append(fragments, e.Value)
	}
	assert.Contains(t, fragments, "There isn't a GitHub Pages site here.")
}

// A live site behind a CDN is the overwhelmingly common case, and the CDN's
// takeover conditions are not observable from DNS. Reporting it would put a
// finding on most well-run domains on the internet.
func TestTakeoverEdgeCaseServiceIsSilentWithoutCorroboration(t *testing.T) {
	cdn := takeover.Fingerprint{
		Service: "Fastly", NXDOMAIN: false, Status: takeover.StatusEdgeCase,
		HTTPBody:  []string{"Fastly error: unknown domain"},
		Reference: "https://example.invalid/fastly",
	}
	obs := TakeoverObservation{
		Domain: "example.com",
		Hosts: []TakeoverHost{{
			Host: "www.example.com", CNAME: "example.map.fastly.net",
			Chain:          []string{"example.map.fastly.net"},
			TargetResolves: true, Fingerprint: &cdn,
		}},
	}
	assert.Empty(t, takeoverIDs(t, obs))
}

// A service the database says cannot be claimed by a third party must not be
// reported, however dangling the alias looks: the finding would be an
// accusation the evidence contradicts.
func TestTakeoverNotVulnerableServiceIsSilent(t *testing.T) {
	safe := takeover.Fingerprint{
		Service: "Safe Service", NXDOMAIN: true,
		Status: takeover.StatusNotVulnerable, Reference: "https://example.invalid/safe",
	}
	obs := TakeoverObservation{
		Domain: "example.com",
		Hosts: []TakeoverHost{{
			Host: "x.example.com", CNAME: "gone.safe.invalid",
			Chain: []string{"gone.safe.invalid"}, TargetNXDOMAIN: true, Fingerprint: &safe,
		}},
	}
	assert.Empty(t, takeoverIDs(t, obs))
}

// This is why the wildcard check had to be built first.
func TestTakeoverWildcardReducesConfidence(t *testing.T) {
	obs := TakeoverObservation{
		Domain:          "example.com",
		WildcardPresent: true,
		Hosts: []TakeoverHost{{
			Host: "assets.example.com", CNAME: "old.s3.amazonaws.com",
			Chain:          []string{"old.s3.amazonaws.com"},
			TargetNXDOMAIN: true, Fingerprint: &nxdomainService,
		}},
	}

	findings := Takeover(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 1)
	assert.Equal(t, "SURF-TKO-001", findings[0].ID)
	assert.Equal(t, "low", findings[0].Confidence.String())
}

func TestTakeoverDanglingNameserver(t *testing.T) {
	obs := TakeoverObservation{
		Domain: "example.com",
		Nameservers: []TakeoverNameserver{
			{Host: "ns1.provider.net"},
			{Host: "ns2.gone.invalid", NXDOMAIN: true},
		},
	}
	assert.Equal(t, []string{"SURF-TKO-005"}, takeoverIDs(t, obs))
}

func TestTakeoverHostWithoutAliasIsSilent(t *testing.T) {
	obs := TakeoverObservation{
		Domain: "example.com",
		Hosts:  []TakeoverHost{{Host: "example.com", TargetResolves: true}},
	}
	assert.Empty(t, takeoverIDs(t, obs))
}

// An alias back into the domain's own tree cannot be taken over by anybody:
// the target is already the organisation's. Without this guard "www to the
// apex" — the commonest record on the internet — is reported as third-party
// exposure whenever the organisation's own domain happens to match a
// fingerprint suffix.
func TestTakeoverInternalAliasIsSilent(t *testing.T) {
	obs := TakeoverObservation{
		Domain: "github.com",
		Hosts: []TakeoverHost{{
			Host: "www.github.com", CNAME: "github.com",
			Chain: []string{"github.com"}, TargetResolves: true,
			Fingerprint: &httpOnlyService,
		}},
	}
	assert.Empty(t, takeoverIDs(t, obs))
}
