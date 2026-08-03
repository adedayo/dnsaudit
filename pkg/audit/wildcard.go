package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/adedayo/dnsaudit/pkg/analyse"
)

// wildcardProbeCount is how many random labels are queried.
//
// Spec 012 calls for three. Two would be enough to establish agreement, but a
// third costs one query and defends against the case where two labels collide
// with a real name or with a resolver's negative-answer synthesis.
const wildcardProbeCount = 3

// randomLabel returns a high-entropy DNS label.
//
// The entropy is the whole point: the label must be one no operator would ever
// have registered, otherwise a positive answer says the name exists rather than
// that the zone answers for everything.
func randomLabel() (string, error) {
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("error: cannot generate a wildcard probe label: %w", err)
	}
	// A leading letter keeps the label valid wherever an all-digit label would
	// be rejected or treated as an address.
	return "d" + hex.EncodeToString(buf), nil
}

// probeWildcard queries random labels under the domain and reports what came
// back, leaving the judgement to analyse.Wildcard.
func probeWildcard(ctx context.Context, c *Cache, domain string) (analyse.WildcardObservation, error) {
	obs := analyse.WildcardObservation{Domain: strings.TrimSuffix(domain, ".")}

	for i := 0; i < wildcardProbeCount; i++ {
		label, err := randomLabel()
		if err != nil {
			return obs, err
		}
		name := label + "." + obs.Domain
		probe := analyse.WildcardProbe{Label: name}

		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeCNAME} {
			msg, _, err := c.Exchange(ctx, name, qtype)
			if err != nil || msg == nil {
				// A probe that could not be answered contributes nothing. It
				// is not recorded as an empty answer, because analyse.Wildcard
				// reads an empty answer as "this label does not resolve" and
				// would then conclude there is no wildcard from a query that
				// never completed.
				continue
			}
			for _, rr := range msg.Answer {
				switch r := rr.(type) {
				case *dns.A:
					probe.Addresses = append(probe.Addresses, r.A.String())
				case *dns.AAAA:
					probe.Addresses = append(probe.Addresses, r.AAAA.String())
				case *dns.MX:
					probe.MX = append(probe.MX,
						fmt.Sprintf("%d %s", r.Preference, strings.TrimSuffix(r.Mx, ".")))
				case *dns.CNAME:
					probe.CNAME = strings.TrimSuffix(r.Target, ".")
				}
			}
		}

		obs.Probes = append(obs.Probes, probe)
	}

	return obs, nil
}

// wildcardRecords renders an observation for the Records field, so a reader
// sees the probes the verdict was drawn from rather than only the verdict.
func wildcardRecords(obs analyse.WildcardObservation) []string {
	var records []string
	for _, p := range obs.Probes {
		switch {
		case p.CNAME != "":
			records = append(records, p.Label+" CNAME "+p.CNAME)
		case len(p.Addresses) > 0:
			records = append(records, p.Label+" A/AAAA "+strings.Join(p.Addresses, ", "))
		}
		if len(p.MX) > 0 {
			records = append(records, p.Label+" MX "+strings.Join(p.MX, ", "))
		}
	}
	return records
}
