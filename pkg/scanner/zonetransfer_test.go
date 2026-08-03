package scanner_test

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/scanner"
)

// startAXFRServer runs a TCP nameserver with the supplied handler.
//
// AXFR runs over TCP, so this cannot reuse the UDP mock used elsewhere. The
// end-to-end test matters more here than almost anywhere: a refusal and a
// disclosure are opposite conclusions delivered over the same stream, and only
// a real transfer exercises the code that tells them apart.
func startAXFRServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &dns.Server{Listener: listener, Net: "tcp", Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return listener.Addr().String()
}

func zoneRecords(t *testing.T, count int) []dns.RR {
	t.Helper()

	soa, err := dns.NewRR("example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026080301 7200 3600 1209600 3600")
	require.NoError(t, err)

	records := []dns.RR{soa}
	for i := 0; i < count; i++ {
		rr, err := dns.NewRR("host" + string(rune('a'+i)) + ".example.test. 3600 IN A 192.0.2.1")
		require.NoError(t, err)
		records = append(records, rr)
	}
	return append(records, soa)
}

func TestZoneTransferSucceeds(t *testing.T) {
	addr := startAXFRServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		transfer := new(dns.Transfer)
		channel := make(chan *dns.Envelope)
		go func() {
			channel <- &dns.Envelope{RR: zoneRecords(t, 5)}
			close(channel)
		}()
		_ = transfer.Out(w, r, channel)
	})

	attempt := scanner.AttemptZoneTransfer(context.Background(), "example.test", addr, "ns1.example.test")

	assert.True(t, attempt.Transferred)
	assert.False(t, attempt.Refused)
	assert.Empty(t, attempt.Error)
	assert.Equal(t, 7, attempt.RecordCount) // SOA + 5 hosts + closing SOA
	assert.True(t, attempt.HasSerial)
	assert.Equal(t, uint32(2026080301), attempt.Serial)

	// The finding proves the disclosure; it does not republish the zone.
	assert.LessOrEqual(t, len(attempt.Sample), 5)
}

// A refused transfer is the control working, and must be reported as a refusal
// rather than as a failure to reach the server: the two lead to opposite
// conclusions about the zone.
func TestZoneTransferRefused(t *testing.T) {
	addr := startAXFRServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})

	attempt := scanner.AttemptZoneTransfer(context.Background(), "example.test", addr, "ns1.example.test")

	assert.False(t, attempt.Transferred)
	assert.True(t, attempt.Refused)
}

// An unreachable server must not look like a refusal: that would report an
// untested server as a protected one.
func TestZoneTransferUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	attempt := scanner.AttemptZoneTransfer(context.Background(), "example.test", addr, "ns1.example.test")

	assert.False(t, attempt.Transferred)
	assert.False(t, attempt.Refused)
	assert.NotEmpty(t, attempt.Error)
}

// Many nameservers decline a transfer by answering with no zone rather than
// with an explicit REFUSED. Reading that as a transport failure would report
// most of the internet's correctly configured servers as untested.
func TestZoneTransferDeclinedByEmptyAnswer(t *testing.T) {
	addr := startAXFRServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})

	attempt := scanner.AttemptZoneTransfer(
		context.Background(), "example.test", addr, "ns1.example.test")

	assert.True(t, attempt.Refused)
	assert.False(t, attempt.Transferred)
}

func TestZoneTransferRequiresAnAddress(t *testing.T) {
	attempt := scanner.AttemptZoneTransfer(context.Background(), "example.test", "  ", "ns1.example.test")
	assert.NotEmpty(t, attempt.Error)
	assert.False(t, attempt.Transferred)
}

// Refusal detection depends on the wording miekg/dns uses for a non-success
// transfer response code. If that ever changes, every refusal silently becomes
// an apparent transport failure and the check's negative case stops working —
// so the assumption is asserted here rather than trusted.
func TestRefusalDetectionMatchesTheLibraryWording(t *testing.T) {
	// Servers decline in several ways. NOTIMP and FORMERR are as common as an
	// explicit REFUSED — the BBC's nameservers answer AXFR with FORMERR — so
	// recognising only REFUSED would report most correctly configured servers
	// as untested.
	declines := []int{
		dns.RcodeRefused, dns.RcodeNotAuth,
		dns.RcodeNotImplemented, dns.RcodeFormatError,
	}
	for _, rcode := range declines {
		addr := startAXFRServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(r, rcode)
			_ = w.WriteMsg(m)
		})

		attempt := scanner.AttemptZoneTransfer(
			context.Background(), "example.test", addr, "ns1.example.test")
		assert.True(t, attempt.Refused, "rcode %d should be read as a refusal", rcode)
	}

	// SERVFAIL is a transient internal failure, not a policy decision: a retry
	// might yet hand over the zone, so claiming the control exists would
	// assert something never observed.
	addr := startAXFRServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})
	attempt := scanner.AttemptZoneTransfer(
		context.Background(), "example.test", addr, "ns1.example.test")
	assert.False(t, attempt.Refused)
	assert.NotEmpty(t, attempt.Error)
}
