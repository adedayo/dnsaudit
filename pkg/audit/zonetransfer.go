package audit

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/scanner"
)

// zoneTransferPort is the port AXFR is attempted on.
//
// It is a variable solely so that the end-to-end test can serve a zone from an
// unprivileged port. No production path changes it: binding port 53 requires
// privilege, and a test that cannot run without root is a test that does not
// run.
var zoneTransferPort = "53"

// attemptZoneTransfers asks every authoritative nameserver for the zone.
//
// Each server is tried, not just the first. A zone is only as protected as its
// least well configured server, and the common real-world failure is precisely
// that one secondary was forgotten when the transfer ACL was tightened
// everywhere else — which testing only the first server would miss.
func attemptZoneTransfers(ctx context.Context, c *Cache, domain string) (analyse.ZoneTransferObservation, error) {
	zone := strings.TrimSuffix(domain, ".")
	obs := analyse.ZoneTransferObservation{Domain: zone}

	msg, _, err := c.Exchange(ctx, zone, dns.TypeNS)
	if err != nil {
		if isAbsent(err) {
			return obs, nil
		}
		return obs, err
	}

	for _, rr := range msg.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		host := strings.TrimSuffix(ns.Ns, ".")

		addresses := resolveHost(ctx, c, host)
		if len(addresses) == 0 {
			// A nameserver we cannot reach is recorded as unattempted rather
			// than omitted, so the evidence shows which servers were actually
			// tested. The delegation check reports the unreachability itself.
			obs.Attempts = append(obs.Attempts, analyse.ZoneTransferAttempt{
				Nameserver: host,
				Error:      "the nameserver's address could not be resolved",
			})
			continue
		}

		obs.Attempts = append(obs.Attempts,
			scanner.AttemptZoneTransfer(ctx, zone,
				net.JoinHostPort(addresses[0], zoneTransferPort), host))
	}

	return obs, nil
}
