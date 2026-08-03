package analyse

import (
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// TLSRPTPolicy holds the parsed tags of a TLS-RPT record (RFC 8460).
type TLSRPTPolicy struct {
	// RUA lists the reporting destinations.
	RUA []string
	// Raw is the record as retrieved.
	Raw string
	// Valid is false when the record cannot serve as TLS-RPT.
	Valid bool
	// Reason explains why an invalid record was rejected.
	Reason string
}

// ParseTLSRPT parses a TLS-RPT record published at _smtp._tls.<domain>.
func ParseTLSRPT(record string) TLSRPTPolicy {
	p := TLSRPTPolicy{Raw: strings.TrimSpace(record)}

	tags := strings.Split(p.Raw, ";")
	if len(tags) == 0 || !strings.EqualFold(strings.TrimSpace(tags[0]), "v=TLSRPTv1") {
		p.Reason = "the record does not begin with the required v=TLSRPTv1 tag"
		return p
	}

	for _, tag := range tags[1:] {
		key, value, found := strings.Cut(strings.TrimSpace(tag), "=")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "rua") {
			p.RUA = append(p.RUA, splitURIs(value)...)
		}
	}

	// RFC 8460 §3 defines exactly two destination schemes. Anything else is
	// silently ignored by senders, so reports would never arrive.
	var usable []string
	for _, uri := range p.RUA {
		lower := strings.ToLower(uri)
		if strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "https://") {
			usable = append(usable, uri)
		}
	}
	if len(usable) == 0 {
		if len(p.RUA) == 0 {
			p.Reason = "the mandatory rua= tag is missing"
		} else {
			p.Reason = "no rua= destination uses the mailto: or https: scheme"
		}
		return p
	}

	p.RUA = usable
	p.Valid = true
	return p
}

// TLSRPT evaluates the TLS-RPT records published for a domain.
//
// records must contain every TXT record at _smtp._tls.<domain>; pass an empty
// slice to report absence.
func TLSRPT(o Origin, records []string) []finding.Finding {
	target := o.Target
	name := "_smtp._tls." + strings.TrimSuffix(target, ".")

	if len(records) == 0 {
		return []finding.Finding{finding.New("SURF-TLSRPT-001", target,
			o.txtEvidence(name, "no v=TLSRPTv1 record"))}
	}

	// A domain with several records is no better off than one with none:
	// senders cannot tell which to honour. Reporting the first record's defects
	// alongside the count keeps the operator's next action obvious.
	policy := ParseTLSRPT(records[0])
	if policy.Valid {
		return nil
	}
	return []finding.Finding{
		finding.New("SURF-TLSRPT-002", target,
			o.txtEvidence(name, policy.Raw),
			finding.ComputedEvidence("tlsrpt.record_count", strconv.Itoa(len(records)))).
			WithDescription("Specifically, " + policy.Reason + "."),
	}
}
