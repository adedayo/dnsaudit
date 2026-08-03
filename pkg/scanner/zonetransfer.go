// zonetransfer.go attempts AXFR against a zone's authoritative nameservers.
//
// This is the most intrusive thing vantage does, and it is still only a
// question: "will you give me the zone?" A server configured correctly says no,
// which is the answer being tested for. Nothing is written to disk unless the
// operator asks for it, and the transferred data is discarded once counted.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/adedayo/vantage/pkg/analyse"
)

// maxSampledRecords bounds the evidence retained from a successful transfer.
//
// A disclosed zone can hold hundreds of thousands of records. The finding needs
// to prove the disclosure, not reproduce it: holding an entire zone in memory
// to render three lines of evidence would turn an audit of a large portfolio
// into an out-of-memory failure, and writing it to a report would republish the
// very data the finding says should not have been available.
const maxSampledRecords = 5

// axfrTimeout bounds a single transfer attempt. It is longer than an ordinary
// query timeout because a large zone legitimately takes time to stream, but
// bounded so that one slow server cannot stall an audit.
const axfrTimeout = 20 * time.Second

// AttemptZoneTransfer tries AXFR against one nameserver address and reports
// what happened.
//
// A refusal is not an error: it is the correct behaviour and the expected
// result. It is returned as a value so that callers can distinguish "refused"
// from "we could not reach the server", which are opposite conclusions about
// the same zone.
func AttemptZoneTransfer(ctx context.Context, zone, server, host string) analyse.ZoneTransferAttempt {
	attempt := analyse.ZoneTransferAttempt{Nameserver: host, Address: server}

	addr, err := normaliseAddress(server)
	if err != nil {
		attempt.Error = err.Error()
		return attempt
	}

	ctx, cancel := context.WithTimeout(ctx, axfrTimeout)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(zone))

	transfer := &dns.Transfer{DialTimeout: axfrTimeout, ReadTimeout: axfrTimeout}
	// DialContext rather than DialTimeout, so a cancelled run stops dialling
	// immediately instead of waiting out the timeout on every remaining
	// nameserver.
	dialer := &net.Dialer{Timeout: axfrTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		attempt.Error = err.Error()
		return attempt
	}
	defer func() { _ = conn.Close() }()

	transfer.Conn = &dns.Conn{Conn: conn}
	channel, err := transfer.In(msg, addr)
	if err != nil {
		attempt.Error = err.Error()
		return attempt
	}

	for envelope := range channel {
		if envelope.Error != nil {
			// A refusal arrives as an error on the stream. Distinguishing it
			// from a transport failure is the whole point of this check: one
			// means the server is configured correctly, the other means we
			// learned nothing at all.
			if isRefusal(envelope.Error) {
				attempt.Refused = true
			} else {
				attempt.Error = envelope.Error.Error()
			}
			break
		}

		attempt.Answered = true
		for _, rr := range envelope.RR {
			attempt.RecordCount++
			if soa, ok := rr.(*dns.SOA); ok {
				attempt.Serial, attempt.HasSerial = soa.Serial, true
			}
			// Only a bounded sample is retained; the rest is counted and
			// discarded as it streams past.
			if len(attempt.Sample) < maxSampledRecords {
				attempt.Sample = append(attempt.Sample, compactRR(rr))
			}
		}

		if err := ctx.Err(); err != nil {
			attempt.Error = err.Error()
			break
		}
	}

	// A stream that opened, produced records and ended cleanly is a completed
	// transfer. One that produced records and then failed is a partial
	// disclosure, which is still a disclosure.
	attempt.Transferred = attempt.Answered && attempt.RecordCount > 0
	return attempt
}

// isRefusal reports whether a transfer error is the server declining, rather
// than the connection failing.
//
// The question this check asks is "can an anonymous client obtain the zone?",
// so any definitive response that is not a zone answers it: no. Servers decline
// in several ways — REFUSED and NOTAUTH by policy, NOTIMP and FORMERR by
// pretending not to understand (the BBC's nameservers answer AXFR with FORMERR,
// as dig confirms), and some simply return a response containing no SOA.
// Enumerating only REFUSED would report the majority of correctly configured
// nameservers as untested.
//
// SERVFAIL is deliberately excluded. It signals a transient internal failure
// rather than a policy decision, and a retry might well succeed in obtaining
// the zone; recording it as a refusal would claim a control this tool never
// observed.
func isRefusal(err error) bool {
	if err == nil {
		return false
	}

	// A response carrying no SOA is a server declining to transfer: it
	// answered, and what it returned was not a zone.
	if errors.Is(err, dns.ErrSoa) {
		return true
	}

	var rcode int
	if _, scanned := fmt.Sscanf(err.Error(), errXFRFormat, &rcode); scanned == nil {
		switch rcode {
		case dns.RcodeRefused, dns.RcodeNotAuth, dns.RcodeNotImplemented, dns.RcodeFormatError:
			return true
		default:
			return false
		}
	}

	// Fall back to the plain-language forms a server or proxy may produce.
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "refused") || strings.Contains(text, "not authoritative")
}

// errXFRFormat mirrors the message miekg/dns produces for a non-success
// transfer response code. The regression test below fails if it ever changes,
// which is the point: a silent change here would turn every refusal into an
// apparent transport failure and quietly disable the check's negative case.
const errXFRFormat = "dns: bad xfr rcode: %d"

// compactRR renders a record as a single line of evidence.
func compactRR(rr dns.RR) string {
	return strings.Join(strings.Fields(rr.String()), " ")
}

// normaliseAddress ensures the server address carries a port.
func normaliseAddress(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("error: no nameserver address supplied for the zone transfer")
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server, nil
	}
	return net.JoinHostPort(server, "53"), nil
}
