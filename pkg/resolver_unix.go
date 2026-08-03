//go:build !windows

package vantage

import (
	"net"
	"os"

	"github.com/miekg/dns"
)

// unixResolvConfPaths are the locations searched for a resolver configuration
// on Unix-like systems. /etc/resolv.conf covers Linux, macOS and the BSDs;
// the Termux path keeps the tool usable on Android.
var unixResolvConfPaths = []string{
	"/etc/resolv.conf",
	"/data/data/com.termux/files/usr/etc/resolv.conf",
}

// systemNameservers returns the nameservers configured on Unix-like systems by
// parsing resolv.conf. An empty slice is returned when no configuration can be
// read, allowing the caller to fall back to public resolvers.
func systemNameservers() []string {
	for _, path := range unixResolvConfPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		cfg, err := dns.ClientConfigFromFile(path)
		if err != nil || cfg == nil || len(cfg.Servers) == 0 {
			continue
		}
		port := cfg.Port
		if port == "" {
			port = DefaultPort
		}
		servers := make([]string, 0, len(cfg.Servers))
		for _, s := range cfg.Servers {
			servers = append(servers, net.JoinHostPort(s, port))
		}
		return servers
	}
	return nil
}
