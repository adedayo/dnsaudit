package analyse

import (
	"strconv"
	"strings"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// MXHost is a published mail exchanger together with what resolution revealed
// about it. Retrieval belongs to the caller; the judgement here stays pure.
type MXHost struct {
	// Preference is the MX preference value; lower is tried first.
	Preference int
	// Host is the exchanger hostname, without a trailing dot.
	Host string
	// Resolves reports whether the host has an A or AAAA record.
	Resolves bool
	// IsCNAME reports whether the host is a CNAME alias, which RFC 2181
	// prohibits as an MX target.
	IsCNAME bool
}

// IsNull reports whether this is the null MX of RFC 7505, which declares that a
// domain accepts no mail at all.
func (m MXHost) IsNull() bool {
	return m.Preference == 0 && (m.Host == "" || m.Host == ".")
}

// MX evaluates the mail exchangers published by a domain.
//
// hasAddress reports whether the domain itself has an A or AAAA record. It
// matters because a domain with no MX but with an address record still attracts
// mail: senders fall back to the address record, so the absence of a null MX is
// only worth reporting when there is something to fall back to.
func MX(o Origin, hosts []MXHost, hasAddress bool) []finding.Finding {
	var findings []finding.Finding
	target := o.Target

	// A null MX is a complete policy statement, so none of the hygiene rules
	// below apply: there is deliberately nowhere for mail to go.
	for _, h := range hosts {
		if h.IsNull() {
			return findings
		}
	}

	if len(hosts) == 0 {
		if hasAddress {
			findings = append(findings, finding.New("DNSA-MX-003", target,
				o.txtEvidence(target, "no MX records")))
		}
		return findings
	}

	for _, h := range hosts {
		ev := finding.ComputedEvidence("mx.host",
			strconv.Itoa(h.Preference)+" "+h.Host)

		if !h.Resolves {
			findings = append(findings, finding.New("DNSA-MX-001", target, ev))
			// A host that does not resolve cannot also be diagnosed as a
			// CNAME; reporting both would be two findings for one defect.
			continue
		}
		if h.IsCNAME {
			findings = append(findings, finding.New("DNSA-MX-002", target, ev))
		}
	}

	if len(hosts) == 1 {
		findings = append(findings, finding.New("DNSA-MX-004", target,
			finding.ComputedEvidence("mx.host_count", "1"),
			finding.ComputedEvidence("mx.host", hosts[0].Host)))
	}

	return findings
}

// ParseMX turns "<preference> <host>" strings, as retrieved from DNS, into
// MXHost values. Resolution state is left unset for the caller to fill in.
func ParseMX(records []string) []MXHost {
	var hosts []MXHost
	for _, r := range records {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		pref, host, found := strings.Cut(r, " ")
		if !found {
			host, pref = pref, "0"
		}
		n, err := strconv.Atoi(strings.TrimSpace(pref))
		if err != nil {
			continue
		}
		host = strings.TrimSpace(host)
		// A bare "." is the null MX and must keep its meaning, so only a
		// trailing dot on a real hostname is removed.
		if host != "." {
			host = strings.TrimSuffix(host, ".")
		}
		hosts = append(hosts, MXHost{Preference: n, Host: host})
	}
	return hosts
}
