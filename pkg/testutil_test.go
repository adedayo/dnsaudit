package vantage

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// startMockDNS starts a local mock DNS server on a random UDP port and returns
// the server address and a stop function.
func startMockDNS(t *testing.T, mux *dns.ServeMux) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr = pc.LocalAddr().String()

	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()

	return addr, func() { _ = srv.Shutdown() }
}
