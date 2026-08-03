package audit

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/adedayo/dnsaudit/pkg/analyse"
)

// resolveMXHosts fills in the resolution state that MX hygiene rules need.
//
// The CNAME test is deliberately a direct query for the CNAME type rather than
// an inspection of a chased A-record answer: a resolver following the alias
// returns the address without revealing the intermediate CNAME, which is
// exactly the configuration RFC 2181 prohibits and the one worth reporting.
func resolveMXHosts(ctx context.Context, c *Cache, hosts []analyse.MXHost) []analyse.MXHost {
	resolved := make([]analyse.MXHost, 0, len(hosts))
	for _, h := range hosts {
		if h.IsNull() {
			resolved = append(resolved, h)
			continue
		}

		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			msg, _, err := c.Exchange(ctx, h.Host, qtype)
			if err == nil && len(msg.Answer) > 0 {
				h.Resolves = true
				break
			}
		}

		if msg, _, err := c.Exchange(ctx, h.Host, dns.TypeCNAME); err == nil {
			for _, rr := range msg.Answer {
				if _, ok := rr.(*dns.CNAME); ok {
					h.IsCNAME = true
					break
				}
			}
		}

		// The registrable domain identifies the operator behind the exchanger,
		// which is what DNSA-MX-005 rests on. It is derived here rather than in
		// the judgement because it needs the public suffix list: a two-label
		// approximation would treat two unrelated British organisations, both
		// under .co.uk, as one provider.
		h.Provider = organisationalDomain(h.Host)

		resolved = append(resolved, h)
	}
	return resolved
}

// hasAddress reports whether the domain itself has an A or AAAA record.
func hasAddress(ctx context.Context, c *Cache, domain string) bool {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if msg, _, err := c.Exchange(ctx, domain, qtype); err == nil && len(msg.Answer) > 0 {
			return true
		}
	}
	return false
}

// mxHosts returns the domain's mail exchanger hostnames, reusing the run cache.
func mxHosts(ctx context.Context, c *Cache, domain string) []string {
	msg, _, err := c.Exchange(ctx, domain, dns.TypeMX)
	if err != nil {
		return nil
	}
	var hosts []string
	for _, rr := range msg.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			hosts = append(hosts, strings.TrimSuffix(mx.Mx, "."))
		}
	}
	return hosts
}

// climbCAA performs the RFC 8659 §3 tree-climbing search, returning the first
// policy found and the label that supplied it.
func climbCAA(ctx context.Context, c *Cache, domain string) analyse.CAAPolicy {
	suffix, _ := publicsuffix.PublicSuffix(strings.TrimSuffix(domain, "."))

	for _, name := range analyse.CAAAncestors(domain, suffix) {
		msg, _, err := c.Exchange(ctx, name, dns.TypeCAA)
		if err != nil {
			continue
		}

		var records []string
		for _, rr := range msg.Answer {
			if caa, ok := rr.(*dns.CAA); ok {
				records = append(records, fmt.Sprintf("%d %s %q", caa.Flag, caa.Tag, caa.Value))
			}
		}
		if len(records) == 0 {
			continue
		}

		return analyse.CAAPolicy{
			Records:   analyse.ParseCAA(records),
			Source:    name,
			Inherited: !strings.EqualFold(name, strings.TrimSuffix(domain, ".")),
		}
	}

	return analyse.CAAPolicy{}
}

// dmarcEnforcing reports whether the domain's DMARC policy is quarantine or
// reject, which BIMI requires.
func dmarcEnforcing(ctx context.Context, c *Cache, domain string) bool {
	txts, _, err := c.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return false
	}
	for _, txt := range txts {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
			continue
		}
		switch analyse.ParseDMARC(txt).Policy {
		case "quarantine", "reject":
			return true
		}
	}
	return false
}

// cacheDMARCResolver adapts the run cache to the DMARC evaluator's interface.
type cacheDMARCResolver struct {
	cache *Cache
}

func (c cacheDMARCResolver) TXT(ctx context.Context, name string) ([]string, error) {
	records, _, err := c.cache.LookupTXT(ctx, name)
	if err != nil {
		if isAbsent(err) {
			return nil, nil
		}
		return nil, err
	}
	return records, nil
}

// organisationalDomain returns the registrable domain for a name.
func organisationalDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	suffix, _ := publicsuffix.PublicSuffix(domain)
	return analyse.OrganisationalDomain(domain, suffix)
}
