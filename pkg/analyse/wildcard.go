package analyse

import (
	"sort"
	"strconv"
	"strings"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// WildcardProbe is the answer a single random label elicited from the zone.
//
// Retrieval belongs to the caller, as everywhere else in this package: the
// labels are generated and queried by pkg/audit, and only the judgement lives
// here, so the false-positive reasoning below is testable without a resolver.
type WildcardProbe struct {
	// Label is the fully qualified name queried, retained as evidence so a
	// reader can reproduce the observation.
	Label string
	// Addresses are the A and AAAA answers, as text.
	Addresses []string
	// MX are the exchangers returned, as "<preference> <host>".
	MX []string
	// CNAME is the alias target, without a trailing dot, or "" if none.
	CNAME string
}

// WildcardObservation is the set of probes performed against one domain.
type WildcardObservation struct {
	// Domain is the zone probed.
	Domain string
	// Probes are the random-label answers.
	Probes []WildcardProbe
}

// minimumProbes is the number of random labels that must agree before a
// wildcard is asserted.
//
// One label is not evidence: a single answer can come from a resolver that
// synthesises replies, from a captive network, or from a name that genuinely
// exists by coincidence. Requiring agreement across independent high-entropy
// labels is what separates "this zone answers for everything" from "this one
// query happened to be answered".
const minimumProbes = 2

// HasWildcardAddress reports whether the observation shows a wildcard A or
// AAAA record.
//
// Exported because subdomain-takeover reasoning depends on it: in a zone with a
// wildcard, a dangling CNAME's target still resolves, so NXDOMAIN-based
// conclusions are unavailable and a takeover finding drawn from them would be
// invented rather than observed.
func (o WildcardObservation) HasWildcardAddress() bool {
	_, ok := o.consistent(func(p WildcardProbe) []string { return p.Addresses })
	return ok
}

// Wildcard evaluates random-label probes for catch-all records.
func Wildcard(o Origin, obs WildcardObservation) []finding.Finding {
	var findings []finding.Finding
	target := o.Target

	count := finding.ComputedEvidence("wildcard.probes", strconv.Itoa(len(obs.Probes)))

	if addresses, ok := obs.consistent(func(p WildcardProbe) []string { return p.Addresses }); ok {
		findings = append(findings, finding.New("DNSA-WILD-001", target,
			finding.DNSEvidence(obs.Probes[0].Label, "A/AAAA", strings.Join(addresses, ", "), o.Source),
			count))
	}

	if exchangers, ok := obs.consistent(func(p WildcardProbe) []string { return p.MX }); ok {
		findings = append(findings, finding.New("DNSA-WILD-002", target,
			finding.DNSEvidence(obs.Probes[0].Label, "MX", strings.Join(exchangers, ", "), o.Source),
			count))
	}

	if alias, ok := obs.consistent(func(p WildcardProbe) []string {
		if p.CNAME == "" {
			return nil
		}
		return []string{p.CNAME}
	}); ok && externalTo(obs.Domain, alias[0]) {
		findings = append(findings, finding.New("DNSA-WILD-003", target,
			finding.DNSEvidence(obs.Probes[0].Label, "CNAME", alias[0], o.Source),
			count))
	}

	return findings
}

// consistent returns the answer every probe gave, when they all gave the same
// non-empty one.
//
// Disagreement is deliberately not reported as a wildcard. A zone behind
// round-robin or geographic steering returns different addresses for the same
// wildcard, so this is a source of false negatives; but the alternative — a
// wildcard asserted from answers that never matched — would make the takeover
// suppression above fire on evidence that does not support it.
func (o WildcardObservation) consistent(extract func(WildcardProbe) []string) ([]string, bool) {
	if len(o.Probes) < minimumProbes {
		return nil, false
	}

	var want []string
	for i, p := range o.Probes {
		got := normalise(extract(p))
		if len(got) == 0 {
			return nil, false
		}
		if i == 0 {
			want = got
			continue
		}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			return nil, false
		}
	}
	return want, true
}

// normalise lower-cases, trims and sorts an answer set so that two answers
// differing only in order or presentation compare equal.
func normalise(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), ".")))
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// externalTo reports whether a CNAME target lies outside the domain's own tree,
// which is what makes a wildcard alias interesting: it hands every unregistered
// name under the domain to somebody else's infrastructure.
func externalTo(domain, targetName string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	targetName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(targetName), "."))
	if domain == "" || targetName == "" {
		return false
	}
	return targetName != domain && !strings.HasSuffix(targetName, "."+domain)
}
