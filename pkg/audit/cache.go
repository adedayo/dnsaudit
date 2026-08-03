package audit

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"

	d "github.com/adedayo/dnsaudit/pkg"
)

// Cache memoises DNS answers for the duration of a single run.
//
// Without it an aggregate audit is wasteful and slow: the MX set alone is
// needed by the SPF, DANE, MTA-STS and mail-hygiene checks, and querying it
// four times is four times the latency and four times the load on someone
// else's nameservers. Caching also makes a run self-consistent — every check
// reasons about the same answer, so two checks can never disagree because a
// record changed underneath them.
//
// The cache is per-run by design. It is never persisted, so a fresh invocation
// always sees current data; stale security posture would be worse than slow.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	// hits and misses support the concurrency tests and --progress reporting.
	hits, misses int
}

type cacheEntry struct {
	once   sync.Once
	msg    *dns.Msg
	server string
	err    error
}

// NewCache creates an empty cache.
func NewCache() *Cache {
	return &Cache{entries: map[string]*cacheEntry{}}
}

// Exchange performs a DNS query, reusing an in-flight or completed result for
// the same question.
//
// Concurrent callers asking the same question share one query rather than
// racing: the first to arrive performs it and the others block on the same
// sync.Once. This matters because checks run in parallel, and without it the
// cache would reduce repeats but not the thundering herd at start-up.
func (c *Cache) Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error) {
	if c == nil {
		return d.ExchangeFrom(ctx, name, qtype)
	}

	key := fmt.Sprintf("%s/%d", dns.Fqdn(name), qtype)

	c.mu.Lock()
	entry, ok := c.entries[key]
	if !ok {
		entry = &cacheEntry{}
		c.entries[key] = entry
		c.misses++
	} else {
		c.hits++
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		entry.msg, entry.server, entry.err = d.ExchangeFrom(ctx, name, qtype)
	})
	return entry.msg, entry.server, entry.err
}

// LookupTXT retrieves TXT records through the cache.
func (c *Cache) LookupTXT(ctx context.Context, domain string) ([]string, string, error) {
	msg, server, err := c.Exchange(ctx, domain, dns.TypeTXT)
	if err != nil {
		return nil, server, err
	}
	var txts []string
	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			txts = append(txts, joinTXT(t))
		}
	}
	if len(txts) == 0 {
		return nil, server, d.ErrNotFound
	}
	return txts, server, nil
}

// joinTXT concatenates the strings of a TXT record back into the value the
// operator published.
//
// A TXT record longer than 255 bytes travels as several strings. Treating them
// as separate records splits a 2048-bit DKIM key into unparseable fragments,
// and makes one long SPF record look like the duplicate that RFC 7208 treats
// as a PermError — inventing findings out of a wire-format detail.
func joinTXT(t *dns.TXT) string {
	return strings.Join(t.Txt, "")
}

// Stats reports cache hits and misses, for tests and progress output.
func (c *Cache) Stats() (hits, misses int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}
