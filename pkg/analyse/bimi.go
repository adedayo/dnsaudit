package analyse

import (
	"strings"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// BIMIRecord holds the parsed tags of a BIMI record.
type BIMIRecord struct {
	// Location is the l= tag: where the logo is served.
	Location string
	// Authority is the a= tag: the Verified Mark Certificate location.
	Authority string
	Raw       string
	// Valid is false when the record is not usable BIMI.
	Valid  bool
	Reason string
}

// ParseBIMI parses a BIMI record. As elsewhere, an unusable record is reported
// as a finding rather than an error.
func ParseBIMI(record string) BIMIRecord {
	b := BIMIRecord{Raw: strings.TrimSpace(record)}

	tags := strings.Split(b.Raw, ";")
	if len(tags) == 0 || !strings.EqualFold(strings.TrimSpace(tags[0]), "v=BIMI1") {
		b.Reason = "the record does not begin with the required v=BIMI1 tag"
		return b
	}

	for _, tag := range tags[1:] {
		key, value, found := strings.Cut(strings.TrimSpace(tag), "=")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "l":
			b.Location = strings.TrimSpace(value)
		case "a":
			b.Authority = strings.TrimSpace(value)
		}
	}

	b.Valid = true
	return b
}

// BIMI evaluates a BIMI record.
//
// dmarcEnforcing reports whether the domain's DMARC policy is quarantine or
// reject. BIMI has no effect without one, so the prerequisite is evaluated
// here rather than left for the operator to infer.
//
// Absence of a BIMI record is deliberately not a finding: BIMI is optional
// branding, and reporting every domain that has not adopted it would be noise.
func BIMI(o Origin, records []string, dmarcEnforcing bool) []finding.Finding {
	if len(records) == 0 {
		return nil
	}

	var findings []finding.Finding
	target := o.Target
	name := "default._bimi." + strings.TrimSuffix(target, ".")

	record := ParseBIMI(records[0])
	ev := o.txtEvidence(name, record.Raw)

	if !record.Valid {
		// There is no catalogued malformed-BIMI rule, and inventing a severity
		// for a cosmetic record would overstate it. The location rule below
		// carries the operator's actual next step.
		return append(findings, finding.New("DNSA-BIMI-002", target, ev).
			WithDescription("Specifically, "+record.Reason+"."))
	}

	if !dmarcEnforcing {
		findings = append(findings, finding.New("DNSA-BIMI-001", target, ev,
			finding.ComputedEvidence("bimi.dmarc_enforcing", "false")))
	}

	if !strings.HasPrefix(strings.ToLower(record.Location), "https://") {
		findings = append(findings, finding.New("DNSA-BIMI-002", target, ev,
			finding.ComputedEvidence("bimi.l", record.Location)))
	}

	if record.Authority == "" {
		findings = append(findings, finding.New("DNSA-BIMI-003", target, ev))
	}

	return findings
}
