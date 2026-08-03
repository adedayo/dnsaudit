package vantage

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// DefaultPort is the port assumed when a resolver address omits one.
const DefaultPort = "53"

// ResolverEnvVar is the name of the environment variable that can be used to
// override the resolvers used by vantage. It accepts a comma-separated list of
// addresses, with or without a port, e.g.:
//
//	VANTAGE_RESOLVERS="1.1.1.1,8.8.8.8:53,[2606:4700:4700::1111]:53"
const ResolverEnvVar = "VANTAGE_RESOLVERS"

// LegacyResolverEnvVar is the name this variable had before the rename from
// dnsaudit to vantage. It is still honoured, with lower precedence than
// ResolverEnvVar, because the failure mode otherwise is silent: a host that
// exported the old name would fall back to the system resolvers and keep
// producing results, just not the ones the operator configured. A changed
// resolver changes what the audit sees, so this must not go unnoticed.
const LegacyResolverEnvVar = "DNSAUDIT_RESOLVERS"

// FallbackResolvers are well-known public resolvers used as a last resort when
// the operating system's resolver configuration cannot be determined. This
// guarantees that vantage remains functional on any platform, including
// minimal containers and Windows hosts with unusual network configurations.
var FallbackResolvers = []string{
	"1.1.1.1:53",                // Cloudflare
	"8.8.8.8:53",                // Google
	"9.9.9.9:53",                // Quad9
	"[2606:4700:4700::1111]:53", // Cloudflare IPv6
}

var (
	resolverMu sync.RWMutex
	// overrideResolvers, when non-empty, takes precedence over discovery.
	overrideResolvers []string
	// cachedResolvers holds the result of discovery so that the (potentially
	// syscall-heavy) platform lookup is performed at most once.
	cachedResolvers []string
)

// SetResolvers overrides the resolvers used for all DNS queries. Addresses may
// be given with or without a port; port 53 is assumed when omitted. Calling it
// with no arguments clears the override and restores platform auto-discovery.
func SetResolvers(servers ...string) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	overrideResolvers = normaliseServers(servers)
}

// ResetResolverCache clears the cached auto-discovered resolvers, forcing the
// next query to re-read the platform configuration. Useful for long-running
// processes whose network configuration may change.
func ResetResolverCache() {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	cachedResolvers = nil
}

// Resolvers returns the ordered list of resolver addresses ("host:port") that
// will be used for DNS queries. Resolution order is:
//
//  1. Explicit override set via SetResolvers (e.g. the --resolver CLI flag).
//  2. The VANTAGE_RESOLVERS environment variable, or DNSAUDIT_RESOLVERS if
//     only the latter is set.
//  3. Platform-specific system configuration:
//     - Unix-like (Linux, macOS, BSD): /etc/resolv.conf
//     - Windows: GetAdaptersAddresses (IP Helper API)
//  4. Well-known public resolvers (FallbackResolvers).
//
// This layered approach makes the tool platform independent: it works on Linux,
// macOS and Windows, and degrades gracefully rather than failing when no system
// configuration is available.
func Resolvers() []string {
	resolverMu.RLock()
	if len(overrideResolvers) > 0 {
		defer resolverMu.RUnlock()
		return append([]string(nil), overrideResolvers...)
	}
	if len(cachedResolvers) > 0 {
		defer resolverMu.RUnlock()
		return append([]string(nil), cachedResolvers...)
	}
	resolverMu.RUnlock()

	resolverMu.Lock()
	defer resolverMu.Unlock()
	if len(cachedResolvers) == 0 {
		cachedResolvers = discoverResolvers()
	}
	return append([]string(nil), cachedResolvers...)
}

// discoverResolvers performs the environment then platform then fallback lookup.
func discoverResolvers() []string {
	for _, name := range []string{ResolverEnvVar, LegacyResolverEnvVar} {
		env := strings.TrimSpace(os.Getenv(name))
		if env == "" {
			continue
		}
		if servers := normaliseServers(strings.Split(env, ",")); len(servers) > 0 {
			return servers
		}
	}
	if servers := normaliseServers(systemNameservers()); len(servers) > 0 {
		return servers
	}
	return append([]string(nil), FallbackResolvers...)
}

// normaliseServers cleans, de-duplicates and port-qualifies resolver addresses,
// discarding any entry that is not a usable address.
func normaliseServers(servers []string) []string {
	seen := make(map[string]struct{}, len(servers))
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		addr, err := normaliseServer(s)
		if err != nil {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// normaliseServer returns the address in "host:port" form, appending the
// default DNS port when absent and bracketing bare IPv6 literals.
func normaliseServer(server string) (string, error) {
	s := strings.TrimSpace(server)
	if s == "" {
		return "", fmt.Errorf("error: empty resolver address")
	}

	// Already has a port (this also handles "[::1]:53").
	if host, port, err := net.SplitHostPort(s); err == nil && host != "" && port != "" {
		return net.JoinHostPort(host, port), nil
	}

	// Bare address; strip any IPv6 brackets and any zone-scoped suffix handling
	// is left to net.JoinHostPort.
	host := strings.Trim(s, "[]")
	if host == "" {
		return "", fmt.Errorf("error: invalid resolver address %q", server)
	}
	return net.JoinHostPort(host, DefaultPort), nil
}
