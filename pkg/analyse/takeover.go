package analyse

import (
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/takeover"
)

// TakeoverHost is one assessed name and what resolution revealed about the
// service it points at.
type TakeoverHost struct {
	// Host is the name assessed.
	Host string
	// CNAME is the terminal target of the alias chain, without a trailing dot.
	CNAME string
	// Chain is the full alias chain, for evidence.
	Chain []string
	// TargetResolves reports whether the terminal target has an address.
	TargetResolves bool
	// TargetNXDOMAIN reports that the resolver answered NXDOMAIN for the
	// target — a definitive "this name does not exist", not a failure to ask.
	TargetNXDOMAIN bool
	// Fingerprint is the matched service, when the target matched one.
	Fingerprint *takeover.Fingerprint
	// HTTPFetched reports that a corroborating HTTP request obtained a
	// response. A request that failed leaves this false, so that the absence
	// of a claim-me fingerprint is never read as proof the name is in use.
	HTTPFetched bool
	// HTTPUnclaimed reports that the response carried one of the service's
	// claim-me fingerprints.
	HTTPUnclaimed bool
	// HTTPMatched is the fragment that matched, retained as evidence.
	HTTPMatched string
	// HTTPURL is the address that produced the response.
	HTTPURL string
}

// TakeoverNameserver is a delegated nameserver and whether its name exists.
type TakeoverNameserver struct {
	Host string
	// NXDOMAIN reports that the nameserver's own name does not exist, which is
	// the registerable, catastrophic case.
	NXDOMAIN bool
}

// TakeoverObservation is everything retrieval gathered for the takeover rules.
type TakeoverObservation struct {
	// Domain is the zone assessed.
	Domain string
	// Hosts are the names examined.
	Hosts []TakeoverHost
	// Nameservers are the zone's delegated nameservers.
	Nameservers []TakeoverNameserver
	// WildcardPresent reports that the zone answers for names that were never
	// registered, which undermines every NXDOMAIN-based conclusion below.
	WildcardPresent bool
	// HTTPCorroborated reports that HTTP corroboration was performed. It is
	// false under --no-network and in profiles that do not permit egress, and
	// governs whether an unverifiable service is reported as unverified.
	HTTPCorroborated bool
}

// Takeover evaluates hosts for claimable third-party services and dangling
// aliases.
func Takeover(o Origin, obs TakeoverObservation) []finding.Finding {
	var findings []finding.Finding

	for _, h := range obs.Hosts {
		findings = append(findings, assessHost(o, obs, h)...)
	}

	for _, ns := range obs.Nameservers {
		if !ns.NXDOMAIN {
			continue
		}
		findings = append(findings, finding.New("SURF-TKO-005", o.Target,
			finding.ComputedEvidence("takeover.nameserver", ns.Host)))
	}

	return findings
}

// assessHost applies the alias rules to a single name.
func assessHost(o Origin, obs TakeoverObservation, h TakeoverHost) []finding.Finding {
	if h.CNAME == "" {
		return nil
	}

	// An alias pointing back inside the domain under assessment is not a
	// takeover candidate at all: claiming the target would mean claiming a
	// name the organisation already controls. Without this guard an internal
	// redirect — www to the apex is the commonest record on the internet —
	// matches any fingerprint whose suffix happens to be the organisation's
	// own domain, and is reported as third-party exposure.
	if inBailiwick(obs.Domain, h.CNAME) {
		return nil
	}

	evidence := []finding.Evidence{
		finding.DNSEvidence(h.Host, "CNAME", h.CNAME, o.Source),
	}
	if len(h.Chain) > 1 {
		evidence = append(evidence,
			finding.ComputedEvidence("takeover.chain", strings.Join(h.Chain, " -> ")))
	}

	if h.Fingerprint == nil {
		if !h.TargetNXDOMAIN {
			return nil
		}
		return []finding.Finding{
			withWildcardCaveat(obs, finding.New("SURF-TKO-004", o.Target, evidence...)),
		}
	}

	f := h.Fingerprint
	evidence = append(evidence,
		finding.ComputedEvidence("takeover.service", f.Service),
		finding.ComputedEvidence("takeover.status", string(f.Status)),
		finding.ComputedEvidence("takeover.reference", f.Reference))

	// A service that documents no way for a third party to claim an abandoned
	// name is not a finding, however dangling the record looks. Reporting it
	// would be an accusation the database itself contradicts.
	if f.Status == takeover.StatusNotVulnerable {
		return nil
	}

	// An HTTP response carrying the service's claim-me page is the strongest
	// evidence available, stronger even than NXDOMAIN: it is the service
	// itself saying nobody holds this name. It is therefore assessed first,
	// and reported whether or not the target still resolves — several
	// providers keep the CNAME target resolvable and answer with an error page
	// long after the account behind it has gone.
	if h.HTTPUnclaimed {
		evidence = append(evidence,
			finding.ComputedEvidence("takeover.http_url", h.HTTPURL),
			finding.ComputedEvidence("takeover.http_fingerprint", h.HTTPMatched))
		return []finding.Finding{
			withWildcardCaveat(obs, finding.New("SURF-TKO-002", o.Target, evidence...)),
		}
	}

	if h.TargetNXDOMAIN {
		return []finding.Finding{
			withWildcardCaveat(obs, finding.New("SURF-TKO-001", o.Target, evidence...)),
		}
	}

	// The target resolves. For services where a dangling name leaves the
	// target unresolvable, that means the name is claimed and in use: there is
	// nothing to report. For the rest, DNS cannot tell a live service from an
	// abandoned one, and only HTTP corroboration can — so the finding says
	// exactly that rather than implying a defect.
	if f.NXDOMAIN || !h.TargetResolves {
		return nil
	}
	if h.HTTPFetched {
		// The service answered and did not show a claim-me page, so the name
		// is in use. Reporting it as unverified after having verified it would
		// be worse than not having looked.
		return nil
	}

	// Only services where an abandoned name can be claimed by anybody are
	// worth an unverified report. An edge-case service — a CDN, typically —
	// requires conditions this tool cannot observe, and a live site fronted by
	// one is the overwhelmingly common case. Reporting those would put a
	// finding on most of the internet's well-run domains and teach readers to
	// skip the rule before it ever caught a real abandoned name.
	if f.Status != takeover.StatusVulnerable {
		return nil
	}

	return []finding.Finding{
		finding.New("SURF-TKO-003", o.Target, evidence...).
			WithConfidence(finding.ConfidenceLow).
			WithDescription("The alias target resolves, and this service cannot be " +
				"distinguished from an abandoned one using DNS alone. No claim is made that " +
				"the name is vulnerable; it is reported so that an operator can confirm the " +
				"service is still theirs."),
	}
}

// withWildcardCaveat reduces confidence when a wildcard makes the observation
// less trustworthy than it appears.
//
// In a zone answering for every name, a host's CNAME may be the wildcard's
// rather than a record the operator published, so the alias may describe a name
// nobody ever created. The finding is kept — a genuinely dangling alias in a
// wildcard zone is still a takeover — but it must not be presented with the
// confidence of an observation the wildcard has undermined.
func withWildcardCaveat(obs TakeoverObservation, f finding.Finding) finding.Finding {
	if !obs.WildcardPresent {
		return f
	}
	return f.WithConfidence(finding.ConfidenceLow).
		WithEvidence(finding.ComputedEvidence("takeover.wildcard_zone", "true")).
		WithDescription("The zone answers for names that were never registered, so this " +
			"alias may have been synthesised by the wildcard rather than published " +
			"deliberately. Confirm the record exists before acting on this finding.")
}
