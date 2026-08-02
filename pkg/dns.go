package dnsaudit

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)



// defaultTimeout is the timeout for DNS queries if the context has no deadline.
const defaultTimeout = 15 * time.Second

// exchange performs a DNS query for the given name and qtype using the provided context.
func exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
    // Ensure name is fully qualified.
    fqdn := dns.Fqdn(name)
    m := new(dns.Msg)
    m.SetQuestion(fqdn, qtype)
    m.RecursionDesired = true

    // Determine timeout.
    deadline, ok := ctx.Deadline()
    timeout := defaultTimeout
    if ok {
        timeout = time.Until(deadline)
        if timeout <= 0 {
            return nil, fmt.Errorf("error: context deadline exceeded")
        }
    }

    client := new(dns.Client)
    client.Timeout = timeout
    // Use system resolver configuration.
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return nil, fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    // Prefer the first nameserver.
    server := servers.Servers[0] + ":" + servers.Port
    resp, _, err := client.ExchangeContext(ctx, m, server)
    if err != nil {
        return nil, fmt.Errorf("error: dns query failed: %w", err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return nil, fmt.Errorf("error: dns response code %d", resp.Rcode)
    }
    return resp, nil
}

// LookupTXT retrieves TXT records for the given domain using miekg/dns.
func LookupTXT(ctx context.Context, domain string) ([]string, error) {
    resp, err := exchange(ctx, domain, dns.TypeTXT)
    if err != nil {
        return nil, err
    }
    var txts []string
    for _, rr := range resp.Answer {
        if t, ok := rr.(*dns.TXT); ok {
            txts = append(txts, t.Txt...)
        }
    }
    if len(txts) == 0 {
        return nil, fmt.Errorf("error: not found")
    }
    return txts, nil
}
