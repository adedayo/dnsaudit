package analyse

import (
	"sort"
	"strconv"
	"strings"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// CTHost is one name discovered in a certificate, together with what resolution
// revealed about it.
type CTHost struct {
	// Host is the name.
	Host string
	// Resolves reports whether the name has an address, an alias or a
	// delegation.
	Resolves bool
	// NXDOMAIN reports that the resolver answered definitively that the name
	// does not exist. It is not the negation of Resolves: a query that failed
	// leaves both false, and nothing may be concluded from that.
	NXDOMAIN bool
	// Issuer is the certificate authority that certified the name.
	Issuer string
	// Expiry is when the most recent certificate for the name expires,
	// formatted for evidence.
	Expiry string
}

// CTObservation is everything Certificate Transparency enumeration found.
type CTObservation struct {
	// Domain is the zone assessed.
	Domain string
	// Source names the log service the data came from.
	Source string
	// Hosts are the discovered names and their resolution state.
	Hosts []CTHost
	// WildcardNames are wildcard identities covering the domain.
	WildcardNames []string
	// CertificateCount is how many issuances were examined.
	CertificateCount int
}

// internalKeywords are the labels that suggest a name was meant for internal
// use.
//
// The list is deliberately short and specific. A keyword heuristic can only
// ever suggest, and a long list of loose terms would fire on ordinary public
// names — "dev" inside "developer.example.com", say — until readers stopped
// looking. Matching is against whole labels for the same reason.
var internalKeywords = map[string]bool{
	"vpn": true, "internal": true, "intranet": true, "corp": true,
	"staging": true, "stage": true, "uat": true, "qa": true, "test": true,
	"dev": true, "sandbox": true, "preprod": true,
	"jira": true, "confluence": true, "jenkins": true, "gitlab": true,
	"admin": true, "adminer": true, "phpmyadmin": true, "grafana": true,
	"kibana": true, "nagios": true, "vcenter": true, "citrix": true,
	"backup": true, "db": true, "database": true, "ldap": true,
}

// CertificateTransparency evaluates what public certificate issuance reveals.
func CertificateTransparency(o Origin, obs CTObservation) []finding.Finding {
	var findings []finding.Finding

	for _, h := range obs.Hosts {
		findings = append(findings, assessCTHost(o, h)...)
	}

	for _, name := range obs.WildcardNames {
		// A wildcard covering the apex is worth knowing about because its
		// private key protects every name in the zone at once: one compromise
		// is one compromise of everything, and the certificate cannot be
		// revoked for one host without revoking it for all of them.
		if strings.TrimPrefix(name, "*.") != obs.Domain {
			continue
		}
		findings = append(findings, finding.New("DNSA-CT-003", o.Target,
			finding.ComputedEvidence("ct.wildcard", name),
			finding.ComputedEvidence("ct.source", obs.Source)))
	}

	sort.SliceStable(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// assessCTHost applies the per-name rules.
func assessCTHost(o Origin, h CTHost) []finding.Finding {
	evidence := []finding.Evidence{
		finding.ComputedEvidence("ct.host", h.Host),
	}
	if h.Issuer != "" {
		evidence = append(evidence, finding.ComputedEvidence("ct.issuer", h.Issuer))
	}
	if h.Expiry != "" {
		evidence = append(evidence, finding.ComputedEvidence("ct.expiry", h.Expiry))
	}

	var findings []finding.Finding

	// Only a definitive NXDOMAIN counts. A query that failed says nothing, and
	// a name that resolves is simply in service.
	if h.NXDOMAIN && !h.Resolves {
		findings = append(findings, finding.New("DNSA-CT-001", o.Target, evidence...))
	}

	if label := internalLabel(h.Host); label != "" {
		findings = append(findings, finding.New("DNSA-CT-002", o.Target,
			append(evidence, finding.ComputedEvidence("ct.keyword", label))...).
			// A keyword heuristic suggests; it does not establish. The spec
			// requires this rule to be reported at medium confidence, and the
			// reason is that "test.example.com" may well be a production
			// service for testing somebody else's code.
			WithConfidence(finding.ConfidenceMedium))
	}

	return findings
}

// internalLabel returns the first label of the name that suggests internal use.
//
// Matching is against whole labels rather than substrings, so "developer" does
// not match "dev" and "contest" does not match "test". A substring match would
// make this rule fire on ordinary public names often enough that readers would
// learn to skip it.
func internalLabel(host string) string {
	labels := strings.Split(strings.ToLower(host), ".")
	// The last two labels are the registrable domain in the common case and
	// are not evidence of anything: an organisation called "Test Ltd" is not
	// leaking an internal hostname by owning test.com.
	if len(labels) > 2 {
		labels = labels[:len(labels)-2]
	} else {
		return ""
	}

	for _, label := range labels {
		if internalKeywords[label] {
			return label
		}
		// Numbered variants — dev1, uat2 — are the same signal.
		trimmed := strings.TrimRight(label, "0123456789")
		if trimmed != label && internalKeywords[trimmed] {
			return label
		}
	}
	return ""
}

// CTRecords renders what enumeration found, so a reader sees the inventory and
// not only the exceptions.
func CTRecords(obs CTObservation) []string {
	records := make([]string, 0, len(obs.Hosts)+2)
	records = append(records,
		strconv.Itoa(obs.CertificateCount)+" certificates examined via "+obs.Source,
		strconv.Itoa(len(obs.Hosts))+" distinct hostnames discovered")

	for _, h := range obs.Hosts {
		line := h.Host
		switch {
		case h.Resolves:
			line += " (resolves)"
		case h.NXDOMAIN:
			line += " (NXDOMAIN)"
		default:
			line += " (resolution state unknown)"
		}
		records = append(records, line)
	}
	return records
}

// CTHostNames returns the discovered names, so that the takeover and
// attribution checks can assess names the operator never had to list.
func CTHostNames(obs CTObservation) []string {
	names := make([]string, 0, len(obs.Hosts))
	for _, h := range obs.Hosts {
		names = append(names, h.Host)
	}
	return names
}
