package analyse

import (
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// DMARCPolicy holds the parsed tags of a DMARC record.
type DMARCPolicy struct {
	Policy    string // p=
	Subdomain string // sp=
	Percent   int    // pct=, defaulting to 100
	RUA       []string
	RUF       []string
	ADKIM     string
	ASPF      string
	Raw       string
	// Valid is false when the record could not be parsed as usable DMARC.
	Valid bool
	// Reason explains why an invalid record was rejected.
	Reason string
}

// policyStrength orders the three policy values so that weakening and
// strengthening can be distinguished — needed here for the sp/p comparison, and
// again by the drift detection of spec 013.
var policyStrength = map[string]int{"none": 0, "quarantine": 1, "reject": 2}

// ParseDMARC parses a DMARC record into its tags. It reports Valid=false rather
// than returning an error, because an unparseable record is itself a finding
// worth reporting, not a failure of the tool.
func ParseDMARC(record string) DMARCPolicy {
	p := DMARCPolicy{Raw: strings.TrimSpace(record), Percent: 100}

	tags := strings.Split(p.Raw, ";")
	if len(tags) == 0 || !strings.EqualFold(strings.TrimSpace(tags[0]), "v=DMARC1") {
		p.Reason = "the record does not begin with the required v=DMARC1 tag"
		return p
	}

	for _, tag := range tags[1:] {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		key, value, found := strings.Cut(tag, "=")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch key {
		case "p":
			p.Policy = strings.ToLower(value)
		case "sp":
			p.Subdomain = strings.ToLower(value)
		case "pct":
			if n, err := strconv.Atoi(value); err == nil {
				p.Percent = n
			}
		case "rua":
			p.RUA = splitURIs(value)
		case "ruf":
			p.RUF = splitURIs(value)
		case "adkim":
			p.ADKIM = strings.ToLower(value)
		case "aspf":
			p.ASPF = strings.ToLower(value)
		}
	}

	if _, ok := policyStrength[p.Policy]; !ok {
		if p.Policy == "" {
			p.Reason = "the mandatory p= tag is missing"
		} else {
			p.Reason = "the p= tag has an unrecognised value " + strconv.Quote(p.Policy)
		}
		return p
	}

	p.Valid = true
	return p
}

func splitURIs(value string) []string {
	var uris []string
	for _, u := range strings.Split(value, ",") {
		if u = strings.TrimSpace(u); u != "" {
			uris = append(uris, u)
		}
	}
	return uris
}

// DMARC evaluates the DMARC records published for a domain.
//
// records must contain every TXT record at _dmarc.<domain> beginning with
// "v=DMARC1"; pass an empty slice to report absence.
func DMARC(o Origin, records []string) []finding.Finding {
	var findings []finding.Finding
	target := o.Target
	name := "_dmarc." + strings.TrimSuffix(target, ".")

	if len(records) == 0 {
		return append(findings, finding.New("SURF-DMARC-001", target,
			o.txtEvidence(name, "no v=DMARC1 record")))
	}

	if len(records) > 1 {
		findings = append(findings, finding.New("SURF-DMARC-007", target,
			o.txtEvidence(name, strings.Join(records, " | ")),
			finding.ComputedEvidence("dmarc.record_count", strconv.Itoa(len(records)))))
	}

	policy := ParseDMARC(records[0])
	ev := o.txtEvidence(name, policy.Raw)

	if !policy.Valid {
		return append(findings, finding.New("SURF-DMARC-008", target, ev).
			WithDescription("Specifically, "+policy.Reason+"."))
	}

	if policy.Policy == "none" {
		findings = append(findings, finding.New("SURF-DMARC-002", target, ev,
			finding.ComputedEvidence("dmarc.p", policy.Policy)))
	}

	if policy.Percent < 100 && policy.Policy != "none" {
		findings = append(findings, finding.New("SURF-DMARC-003", target, ev,
			finding.ComputedEvidence("dmarc.pct", strconv.Itoa(policy.Percent))))
	}

	// Only meaningful when the domain policy actually enforces something.
	if policy.Subdomain != "" {
		if sub, ok := policyStrength[policy.Subdomain]; ok {
			if main, ok := policyStrength[policy.Policy]; ok && sub < main {
				findings = append(findings, finding.New("SURF-DMARC-004", target, ev,
					finding.ComputedEvidence("dmarc.p", policy.Policy),
					finding.ComputedEvidence("dmarc.sp", policy.Subdomain)))
			}
		}
	}

	if len(policy.RUA) == 0 {
		findings = append(findings, finding.New("SURF-DMARC-005", target, ev))
	}

	return findings
}
