package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	dnsaudit "github.com/adedayo/dnsaudit/pkg"
	"github.com/adedayo/dnsaudit/pkg/analyse"
	"github.com/adedayo/dnsaudit/pkg/finding"
	"github.com/adedayo/dnsaudit/pkg/scanner"
)

// This file adapts the existing checks to the Check interface and registers
// them. Registration is the only step needed to expose a check everywhere:
// the CLI, the profiles and, in due course, the capability manifest.
//
// Checks whose analysis rules are not yet written (spec 011) still register
// here. They contribute their records and their state to the result, which is
// worth having on its own, and they gain findings the moment their rules land.

func init() {
	Register(spfCheck())
	Register(dmarcCheck())
	Register(dkimCheck())
	Register(mxCheck())
	Register(dnssecCheck())
	Register(nssecCheck())
	Register(caaCheck())
	Register(mtastsCheck())
	Register(ptrCheck())
	Register(tlsrptCheck())
	Register(bimiCheck())
}

// notFound reports the absent state without treating it as a failure.
func notFound(findings ...finding.Finding) (Outcome, error) {
	return Outcome{State: finding.StateNotFound, Findings: findings}, nil
}

// isAbsent reports whether an error means the record is definitively absent.
func isAbsent(err error) bool {
	return errors.Is(err, dnsaudit.ErrNotFound) || strings.Contains(err.Error(), "not found")
}

func spfCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "spf",
			Summary:        "Sender Policy Framework: which hosts may send mail as the domain.",
			Network:        []Network{NetworkDNS},
			Findings:       findingIDs("spf"),
			TypicalQueries: 12,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			txts, server, err := t.Cache.LookupTXT(ctx, t.Domain)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
					records = append(records, txt)
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.SPFRecursive(ctx, origin,
				cacheResolver{t.Cache}, records, sendsMail(ctx, t))
			if len(records) == 0 {
				return notFound(findings...)
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func dmarcCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "dmarc",
			Summary:        "DMARC policy: what receivers should do with unauthenticated mail.",
			Network:        []Network{NetworkDNS},
			Findings:       findingIDs("dmarc"),
			TypicalQueries: 3,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			name := "_dmarc." + t.Domain
			txts, server, err := t.Cache.LookupTXT(ctx, name)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToUpper(txt), "V=DMARC1") {
					records = append(records, txt)
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.DMARCFull(ctx, origin, cacheDMARCResolver{t.Cache},
				records, organisationalDomain(t.Domain))
			if len(records) == 0 {
				return notFound(findings...)
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

// commonDKIMSelectors are the selectors used by the major mail providers.
//
// Probing them is inference, not proof: a domain may use a selector nobody can
// guess. The check therefore reports what it finds but never concludes DKIM is
// absent, because "we looked in the obvious places" is not the same as "it is
// not there" — and reporting the latter would be a plain falsehood.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "s1", "s2",
	"mail", "dkim", "mandrill", "zoho", "everlytickey1", "sig1",
}

func dkimCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "dkim",
			Summary: "DKIM signing keys, probed across the selectors used by common " +
				"providers.",
			Network:        []Network{NetworkDNS},
			Findings:       findingIDs("dkim"),
			TypicalQueries: len(commonDKIMSelectors),
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			var (
				records []string
				keys    []analyse.DKIMKey
				server  string
			)
			for _, selector := range commonDKIMSelectors {
				name := selector + "._domainkey." + t.Domain
				txts, from, err := t.Cache.LookupTXT(ctx, name)
				if err != nil {
					continue
				}
				for _, txt := range txts {
					if !strings.Contains(txt, "p=") {
						continue
					}
					if server == "" {
						server = from
					}
					records = append(records, selector+": "+txt)
					keys = append(keys, analyse.ParseDKIM(selector, txt))
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.DKIM(origin, keys, true)
			if len(records) == 0 {
				// Not "absent": DKIM selectors cannot be enumerated from DNS,
				// so a miss across the common ones proves nothing. Reporting
				// this as not-found would invite the reader to conclude a
				// control is missing when it may simply use a private selector.
				return Outcome{State: finding.StateNotChecked, Findings: findings}, nil
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func mxCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "mx",
			Summary:        "Mail exchangers published by the domain, and their hygiene.",
			Network:        []Network{NetworkDNS},
			Findings:       findingIDs("mx"),
			TypicalQueries: 6,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			msg, _, err := t.Cache.Exchange(ctx, t.Domain, dns.TypeMX)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}
			var records []string
			if msg != nil {
				for _, rr := range msg.Answer {
					if mx, ok := rr.(*dns.MX); ok {
						records = append(records, fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
					}
				}
			}

			origin := analyse.Origin{Target: t.Domain}
			hosts := resolveMXHosts(ctx, t.Cache, analyse.ParseMX(records))
			findings := analyse.MX(origin, hosts, hasAddress(ctx, t.Cache, t.Domain))

			if len(records) == 0 {
				return notFound(findings...)
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func dnssecCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "dnssec",
			Summary:        "DNSSEC signing key presence.",
			Network:        []Network{NetworkDNS},
			Findings:       nil,
			TypicalQueries: 1,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			status, err := scanner.CheckDNSSEC(ctx, t.Domain)
			if err != nil {
				if isAbsent(err) {
					return notFound()
				}
				return Outcome{}, err
			}
			if strings.Contains(strings.ToLower(status), "not") {
				return notFound()
			}
			return Outcome{State: finding.StateOK, Records: []string{status}}, nil
		},
	}
}

func nssecCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "nssec",
			Summary:        "NSEC/NSEC3 denial-of-existence records.",
			Network:        []Network{NetworkDNS},
			Findings:       nil,
			TypicalQueries: 1,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			present, err := scanner.VerifyNSSEC(ctx, t.Domain)
			if err != nil {
				if isAbsent(err) {
					return notFound()
				}
				return Outcome{}, err
			}
			if !present {
				return notFound()
			}
			return Outcome{State: finding.StateOK, Records: []string{"NSEC/NSEC3 present"}}, nil
		},
	}
}

func caaCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "caa",
			Summary:        "Certification Authority Authorisation: which CAs may issue.",
			Network:        []Network{NetworkDNS},
			Findings:       findingIDs("caa"),
			TypicalQueries: 3,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			policy := climbCAA(ctx, t.Cache, t.Domain)
			findings := analyse.CAA(analyse.Origin{Target: t.Domain}, policy)

			if len(policy.Records) == 0 {
				return notFound(findings...)
			}

			records := make([]string, 0, len(policy.Records))
			for _, r := range policy.Records {
				records = append(records,
					fmt.Sprintf("%d %s %q", r.Flags, r.Tag, r.Value))
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func mtastsCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:    "mtasts",
			Summary: "MTA-STS: enforced TLS for inbound mail, including the policy file.",
			// The policy file is fetched over HTTPS, but the check is not
			// excluded by --no-network: the TXT record alone reveals whether
			// MTA-STS is published at all, which is the finding that matters
			// most. In that mode only the policy-dependent rules are skipped.
			Network:                []Network{NetworkDNS, NetworkHTTPS},
			DegradesWithoutNetwork: true,
			Findings:               findingIDs("mtasts"),
			TypicalQueries:         2,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			name := "_mta-sts." + t.Domain
			txts, server, err := t.Cache.LookupTXT(ctx, name)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToUpper(txt), "V=STSV1") {
					records = append(records, txt)
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}

			// A zero policy means no fetch was attempted, which suppresses the
			// rules that depend on the policy file rather than reporting them
			// as failures.
			var policy analyse.MTASTSPolicy
			if len(records) > 0 && !t.NoNetwork {
				policy = scanner.FetchMTASTSPolicy(ctx, t.Domain)
			}

			findings := analyse.MTASTS(origin, records, policy, mxHosts(ctx, t.Cache, t.Domain))
			if len(records) == 0 {
				return notFound(findings...)
			}

			if policy.Raw != "" {
				// Record the policy as its own lines, so the retrieved
				// evidence is readable rather than a whitespace-split blob.
				for _, line := range strings.Split(policy.Raw, "\n") {
					if line = strings.TrimSpace(line); line != "" {
						records = append(records, line)
					}
				}
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func ptrCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "ptr",
			Summary:        "Reverse DNS for the domain's addresses.",
			Network:        []Network{NetworkDNS},
			Findings:       nil,
			TypicalQueries: 2,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			record, err := scanner.ReverseLookupPTR(ctx, t.Domain)
			if err != nil {
				if isAbsent(err) {
					return notFound()
				}
				return Outcome{}, err
			}
			return Outcome{State: finding.StateOK, Records: []string{record}}, nil
		},
	}
}

func tlsrptCheck() Check {
	return CheckFunc{
		Description: Description{
			Name: "tlsrpt",
			Summary: "SMTP TLS Reporting: where receivers report failures to negotiate " +
				"TLS with the domain's mail exchangers.",
			Network:        []Network{NetworkDNS},
			Findings:       findingIDs("tlsrpt"),
			TypicalQueries: 1,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			name := "_smtp._tls." + t.Domain
			txts, server, err := t.Cache.LookupTXT(ctx, name)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToUpper(txt), "V=TLSRPTV1") {
					records = append(records, txt)
				}
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.TLSRPT(origin, records)
			if len(records) == 0 {
				return notFound(findings...)
			}
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

func bimiCheck() Check {
	return CheckFunc{
		Description: Description{
			Name:           "bimi",
			Summary:        "Brand Indicators for Message Identification (default._bimi).",
			Network:        []Network{NetworkDNS},
			Findings:       findingIDs("bimi"),
			TypicalQueries: 2,
		},
		Fn: func(ctx context.Context, t Target) (Outcome, error) {
			name := "default._bimi." + t.Domain
			txts, server, err := t.Cache.LookupTXT(ctx, name)
			if err != nil && !isAbsent(err) {
				return Outcome{}, err
			}

			var records []string
			for _, txt := range txts {
				txt = strings.TrimSpace(txt)
				if strings.HasPrefix(strings.ToUpper(txt), "V=BIMI1") {
					records = append(records, txt)
				}
			}

			if len(records) == 0 {
				// Absence is not a finding: BIMI is optional branding, so the
				// analysis is only run when a record exists.
				return notFound()
			}

			origin := analyse.Origin{Target: t.Domain, Source: server}
			findings := analyse.BIMI(origin, records, dmarcEnforcing(ctx, t.Cache, t.Domain))
			return Outcome{State: finding.StateOK, Records: records, Findings: findings}, nil
		},
	}
}

// sendsMail reports whether the domain publishes usable MX records, reusing the
// run cache so the answer costs at most one query per target.
//
// A failed lookup returns true: assuming the domain sends mail keeps a missing
// SPF record at its full severity. Downgrading a real problem on the strength
// of a query that did not complete is the wrong direction in which to be wrong.
func sendsMail(ctx context.Context, t Target) bool {
	msg, _, err := t.Cache.Exchange(ctx, t.Domain, dns.TypeMX)
	if err != nil {
		return !isAbsent(err)
	}
	for _, rr := range msg.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			if host := strings.TrimSpace(mx.Mx); host != "" && host != "." {
				return true
			}
		}
	}
	return false
}

// findingIDs returns the catalogue IDs belonging to a check, so a check's
// declared findings are derived from the catalogue rather than restated.
func findingIDs(check string) []string {
	entries := finding.CatalogueForCheck(check)
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	return ids
}
