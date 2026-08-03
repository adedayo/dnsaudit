//go:build windows

package vantage

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemNameservers returns the DNS servers configured on the active Windows
// network adapters using the IP Helper API (GetAdaptersAddresses). Windows has
// no resolv.conf, so this is the platform-native equivalent.
//
// Adapters that are not operationally up, and loopback adapters, are skipped.
// An empty slice is returned when nothing usable is found, allowing the caller
// to fall back to public resolvers.
func systemNameservers() []string {
	const (
		flags = windows.GAA_FLAG_SKIP_ANYCAST |
			windows.GAA_FLAG_SKIP_MULTICAST |
			windows.GAA_FLAG_SKIP_FRIENDLY_NAME
		ifOperStatusUp = 1
	)

	adapters, err := adapterAddresses(flags)
	if err != nil {
		return nil
	}

	var servers []string
	for a := adapters; a != nil; a = a.Next {
		if a.OperStatus != ifOperStatusUp {
			continue
		}
		if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		for dnsAddr := a.FirstDnsServerAddress; dnsAddr != nil; dnsAddr = dnsAddr.Next {
			sa, err := dnsAddr.Address.Sockaddr.Sockaddr()
			if err != nil {
				continue
			}
			var ip net.IP
			switch v := sa.(type) {
			case *syscall.SockaddrInet4:
				ip = net.IP(v.Addr[:]).To4()
			case *syscall.SockaddrInet6:
				ip = net.IP(v.Addr[:])
			default:
				continue
			}
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			// Windows advertises site-local anycast placeholders that are not
			// usable resolvers; skip them.
			if isWindowsPlaceholderDNS(ip) {
				continue
			}
			servers = append(servers, net.JoinHostPort(ip.String(), DefaultPort))
		}
	}
	return servers
}

// isWindowsPlaceholderDNS reports whether the address is one of the reserved
// site-local anycast addresses Windows reports when no real resolver is set.
func isWindowsPlaceholderDNS(ip net.IP) bool {
	placeholders := []string{
		"fec0:0:0:ffff::1",
		"fec0:0:0:ffff::2",
		"fec0:0:0:ffff::3",
	}
	for _, p := range placeholders {
		if ip.Equal(net.ParseIP(p)) {
			return true
		}
	}
	return false
}

// adapterAddresses wraps GetAdaptersAddresses, growing the buffer as required.
func adapterAddresses(flags uint32) (*windows.IpAdapterAddresses, error) {
	size := uint32(15000) // documented starting size
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		// addrs points into buf; the interior pointer keeps the whole
		// allocation reachable for as long as the list is in use.
		addrs := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, addrs, &size)
		if err == nil {
			return addrs, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}
