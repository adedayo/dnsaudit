// Package netattr attributes an IP address to a network: the special-purpose
// registry it belongs to, or the cloud provider and region that announces it.
//
// The two halves of this package have deliberately different characters. The
// special-purpose ranges are transcribed from the IANA registries: they are
// small, they change perhaps once a decade, and they are authoritative, so they
// are embedded and a lookup against them is exact. Provider ranges are none of
// those things — they change daily and only the providers know them — so they
// are fetched from each provider's own published file and cached, never
// guessed. An address this package cannot attribute is reported as unattributed
// rather than as "not in a cloud", because a partial answer must not be dressed
// up as a complete one.
package netattr

import (
	"fmt"
	"net/netip"
)

// Category classifies a special-purpose range by what its appearance in public
// DNS actually means.
type Category string

// The categories a special-purpose range may carry.
const (
	// CategoryPrivate is RFC 1918 and IPv6 unique-local space: addresses that
	// are meaningful only inside the organisation's own network.
	CategoryPrivate Category = "private"
	// CategoryCGNAT is RFC 6598 shared address space, used between a carrier
	// and its subscribers.
	CategoryCGNAT Category = "cgnat"
	// CategoryLoopback is the host itself.
	CategoryLoopback Category = "loopback"
	// CategoryLinkLocal is address space valid only on a single link.
	CategoryLinkLocal Category = "link-local"
	// CategoryDocumentation is space reserved for examples, which is never
	// routable and is usually a placeholder somebody forgot to replace.
	CategoryDocumentation Category = "documentation"
	// CategoryReserved is space reserved or unallocated by IANA.
	CategoryReserved Category = "reserved"
	// CategoryUnspecified is the all-zeroes address.
	CategoryUnspecified Category = "unspecified"
	// CategorySpecial is other special-purpose space that is neither private
	// nor a placeholder: multicast, broadcast, protocol assignments.
	CategorySpecial Category = "special"
)

// DisclosesInternalAddressing reports whether a category, published in the
// public DNS, hands an outsider information about the organisation's internal
// network.
//
// Loopback and the unspecified address are excluded on purpose. Both are widely
// and deliberately used to null-route a name that must exist but must not
// resolve anywhere, so treating them as a leak would report a common defensive
// practice as a defect. They are still worth surfacing, but as a weaker claim.
func (c Category) DisclosesInternalAddressing() bool {
	switch c {
	case CategoryPrivate, CategoryCGNAT, CategoryLinkLocal:
		return true
	default:
		return false
	}
}

// SpecialRange is one entry from the IANA special-purpose address registries.
type SpecialRange struct {
	// Prefix is the range.
	Prefix netip.Prefix
	// Name is the registry's name for it.
	Name string
	// Category is what its presence in public DNS means.
	Category Category
	// Reference cites the RFC that reserved it.
	Reference string
}

// specialRanges is transcribed from the IANA IPv4 and IPv6 Special-Purpose
// Address Registries.
//
// This list is complete rather than illustrative. A missing entry would let an
// address that discloses internal addressing pass as an ordinary public one,
// which is a silent false negative in the one rule of this check that carries
// real severity.

// rfc4291 is the IPv6 addressing architecture, which defines several of the
// ranges below.
const rfc4291 = "https://www.rfc-editor.org/rfc/rfc4291"

var specialRanges = mustParseRanges([]struct {
	prefix    string
	name      string
	category  Category
	reference string
}{
	// ---------------------------------------------------------------- IPv4 ---
	{"0.0.0.0/8", "this network", CategoryUnspecified, "https://www.rfc-editor.org/rfc/rfc1122"},
	{"10.0.0.0/8", "private-use", CategoryPrivate, "https://www.rfc-editor.org/rfc/rfc1918"},
	{"100.64.0.0/10", "shared address space (CGNAT)", CategoryCGNAT, "https://www.rfc-editor.org/rfc/rfc6598"},
	{"127.0.0.0/8", "loopback", CategoryLoopback, "https://www.rfc-editor.org/rfc/rfc1122"},
	{"169.254.0.0/16", "link local", CategoryLinkLocal, "https://www.rfc-editor.org/rfc/rfc3927"},
	{"172.16.0.0/12", "private-use", CategoryPrivate, "https://www.rfc-editor.org/rfc/rfc1918"},
	{"192.0.0.0/24", "IETF protocol assignments", CategorySpecial, "https://www.rfc-editor.org/rfc/rfc6890"},
	{"192.0.2.0/24", "documentation (TEST-NET-1)", CategoryDocumentation, "https://www.rfc-editor.org/rfc/rfc5737"},
	{"192.88.99.0/24", "6to4 relay anycast (deprecated)", CategorySpecial, "https://www.rfc-editor.org/rfc/rfc7526"},
	{"192.168.0.0/16", "private-use", CategoryPrivate, "https://www.rfc-editor.org/rfc/rfc1918"},
	{"198.18.0.0/15", "benchmarking", CategoryDocumentation, "https://www.rfc-editor.org/rfc/rfc2544"},
	{"198.51.100.0/24", "documentation (TEST-NET-2)", CategoryDocumentation, "https://www.rfc-editor.org/rfc/rfc5737"},
	{"203.0.113.0/24", "documentation (TEST-NET-3)", CategoryDocumentation, "https://www.rfc-editor.org/rfc/rfc5737"},
	{"224.0.0.0/4", "multicast", CategorySpecial, "https://www.rfc-editor.org/rfc/rfc5771"},
	{"240.0.0.0/4", "reserved for future use", CategoryReserved, "https://www.rfc-editor.org/rfc/rfc1112"},
	{"255.255.255.255/32", "limited broadcast", CategorySpecial, "https://www.rfc-editor.org/rfc/rfc8190"},

	// ---------------------------------------------------------------- IPv6 ---
	{"::/128", "unspecified address", CategoryUnspecified, rfc4291},
	{"::1/128", "loopback address", CategoryLoopback, rfc4291},
	{"::ffff:0:0/96", "IPv4-mapped address", CategorySpecial, rfc4291},
	{"64:ff9b::/96", "IPv4-IPv6 translation", CategorySpecial, "https://www.rfc-editor.org/rfc/rfc6052"},
	{"100::/64", "discard-only address block", CategorySpecial, "https://www.rfc-editor.org/rfc/rfc6666"},
	{"2001::/32", "Teredo", CategorySpecial, "https://www.rfc-editor.org/rfc/rfc4380"},
	{"2001:2::/48", "benchmarking", CategoryDocumentation, "https://www.rfc-editor.org/rfc/rfc5180"},
	{"2001:db8::/32", "documentation", CategoryDocumentation, "https://www.rfc-editor.org/rfc/rfc3849"},
	{"2002::/16", "6to4", CategorySpecial, "https://www.rfc-editor.org/rfc/rfc3056"},
	{"fc00::/7", "unique-local", CategoryPrivate, "https://www.rfc-editor.org/rfc/rfc4193"},
	{"fe80::/10", "link-local unicast", CategoryLinkLocal, rfc4291},
	{"ff00::/8", "multicast", CategorySpecial, rfc4291},
})

// LookupSpecial returns the special-purpose range containing the address.
//
// The most specific match wins, because the registries nest: 192.0.2.0/24 sits
// inside no other entry today, but 100::/64 sits inside space that later
// registry revisions may cover, and a first-match implementation would report
// whichever entry happened to be listed first.
func LookupSpecial(addr netip.Addr) (SpecialRange, bool) {
	addr = addr.Unmap()

	var best SpecialRange
	found := false
	for _, r := range specialRanges {
		if !r.Prefix.Contains(addr) {
			continue
		}
		if !found || r.Prefix.Bits() > best.Prefix.Bits() {
			best, found = r, true
		}
	}
	return best, found
}

// IsGlobalUnicast reports whether an address is ordinary routable space.
func IsGlobalUnicast(addr netip.Addr) bool {
	_, special := LookupSpecial(addr)
	return !special
}

func mustParseRanges(entries []struct {
	prefix    string
	name      string
	category  Category
	reference string
},
) []SpecialRange {
	ranges := make([]SpecialRange, 0, len(entries))
	for _, e := range entries {
		p, err := netip.ParsePrefix(e.prefix)
		if err != nil {
			// A malformed constant is a programming error, and one that would
			// otherwise silently remove a range from the registry.
			panic(fmt.Sprintf("netattr: invalid special-purpose prefix %q: %v", e.prefix, err))
		}
		ranges = append(ranges, SpecialRange{
			Prefix: p, Name: e.name, Category: e.category, Reference: e.reference,
		})
	}
	return ranges
}
