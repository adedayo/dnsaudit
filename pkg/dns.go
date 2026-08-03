package dnsaudit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// ErrNotFound is returned when a query succeeds but yields no usable record.
var ErrNotFound = errors.New("error: not found")

// question builds a recursive query message for the given name and type.
func question(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

// udpBufferSize is the EDNS0 receive buffer advertised on UDP queries. 1232
// bytes is the widely-adopted DNS Flag Day figure: large enough for the
// records this tool retrieves, small enough to stay clear of IP fragmentation,
// which is both unreliable in practice and a spoofing aid.
const udpBufferSize = 1232

// exchangeOnce sends the query to a single resolver, retrying over TCP when the
// UDP response is truncated. The attempt is bounded both by the supplied
// timeout and by the caller's context.
func exchangeOnce(ctx context.Context, addr string, m *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Pace queries per resolver so that a concurrent audit never resembles an
	// attack, and never trips rate limiting that would turn into spurious
	// findings.
	if err := awaitQuerySlot(ctx, addr); err != nil {
		return nil, err
	}

	client := &dns.Client{Timeout: timeout, UDPSize: udpBufferSize}

	// Advertise a larger receive buffer. Without EDNS0 the limit is 512 bytes,
	// which large TXT responses routinely exceed — and a domain with a big SPF
	// include tree is exactly the case worth auditing. The query is sent on a
	// copy so that a retry over TCP re-sends the caller's original message.
	edns := m.Copy()
	edns.SetEdns0(udpBufferSize, false)

	resp, _, err := client.ExchangeContext(ctx, edns, addr)

	// Fall back to TCP not only when the server sets the truncation flag, but
	// also when the response could not be parsed. An oversized answer can fail
	// to unpack before the flag is ever read, and reporting that as an
	// unreachable resolver would hide a perfectly healthy domain behind a
	// transport detail.
	if err != nil || resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: timeout}
		if tcpResp, _, tcpErr := tcp.ExchangeContext(ctx, m, addr); tcpErr == nil {
			return tcpResp, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// ExchangeWithServer performs a DNS query against an explicit resolver address
// ("host" or "host:port"), bypassing resolver discovery. It is useful for
// targeted diagnostics and for testing against a local DNS server.
//
// Because there is no other resolver to fail over to, the attempt is given the
// full lookup budget (TotalTimeout, or the context deadline if sooner) rather
// than the shorter per-resolver QueryTimeout.
func ExchangeWithServer(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	addr, err := normaliseServer(server)
	if err != nil {
		return nil, err
	}
	remaining, err := budget(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := exchangeOnce(ctx, addr, question(name, qtype), remaining)
	if err != nil {
		return nil, fmt.Errorf("error: dns query failed: %w", err)
	}
	return resp, nil
}

// ExchangeRaw performs a DNS query for the given name and qtype and returns the
// raw response without interpreting the response code.
//
// The query is attempted against each resolver returned by Resolvers() in turn,
// so a single unreachable nameserver does not cause the audit to fail. Each
// attempt is bounded by QueryTimeout (short by default, for fast failover) and
// the sequence as a whole by TotalTimeout; both are configurable. Resolver
// discovery is platform independent (see resolver.go), so this behaves
// identically on Linux, macOS and Windows.
func ExchangeRaw(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	resp, _, err := ExchangeRawFrom(ctx, name, qtype)
	return resp, err
}

// ExchangeRawFrom behaves like ExchangeRaw but also reports which resolver
// answered.
//
// Attribution matters for evidence: a finding that says "this is what DNS told
// us" is far weaker than one that says which resolver said it and when. It also
// makes a result reproducible by a reader who may see different answers from
// their own resolver, whether through split-horizon DNS, filtering or an
// outright hijack.
func ExchangeRawFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error) {
	remaining, err := budget(ctx)
	if err != nil {
		return nil, "", err
	}
	deadline := time.Now().Add(remaining)

	servers := Resolvers()
	if len(servers) == 0 {
		return nil, "", fmt.Errorf("error: no DNS resolvers available")
	}

	m := question(name, qtype)
	var lastErr error
	for _, server := range servers {
		remaining = time.Until(deadline)
		if remaining <= 0 {
			if lastErr == nil {
				lastErr = context.DeadlineExceeded
			}
			break
		}
		resp, err := exchangeOnce(ctx, server, m, attemptTimeout(remaining))
		if err == nil {
			return resp, server, nil
		}
		lastErr = err
		// Stop early if the caller cancelled or their deadline expired.
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", fmt.Errorf("error: dns query failed: %w", lastErr)
}

// Exchange performs a DNS query and treats a non-success response code as an
// error.
func Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	resp, _, err := ExchangeFrom(ctx, name, qtype)
	return resp, err
}

// ExchangeFrom behaves like Exchange but also reports which resolver answered.
func ExchangeFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error) {
	resp, server, err := ExchangeRawFrom(ctx, name, qtype)
	if err != nil {
		return nil, "", err
	}
	if resp.Rcode == dns.RcodeNameError {
		// NXDOMAIN is a definitive answer — the name does not exist — not a
		// failure to obtain one. Returning a generic error here would make
		// callers report "check failed" for a question that was answered
		// conclusively, hiding absent records behind an apparent fault.
		return nil, server, ErrNotFound
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, server, fmt.Errorf("error: dns response code %d", resp.Rcode)
	}
	return resp, server, nil
}

// LookupTXT retrieves TXT records for the given domain.
func LookupTXT(ctx context.Context, domain string) ([]string, error) {
	txts, _, err := LookupTXTFrom(ctx, domain)
	return txts, err
}

// LookupTXTFrom retrieves TXT records and reports which resolver answered.
func LookupTXTFrom(ctx context.Context, domain string) ([]string, string, error) {
	resp, server, err := ExchangeFrom(ctx, domain, dns.TypeTXT)
	if err != nil {
		return nil, server, err
	}
	var txts []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			txts = append(txts, t.Txt...)
		}
	}
	if len(txts) == 0 {
		return nil, server, ErrNotFound
	}
	return txts, server, nil
}
