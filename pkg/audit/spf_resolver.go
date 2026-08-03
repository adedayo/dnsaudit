package audit

import (
	"context"

	"github.com/miekg/dns"
)

// cacheResolver adapts the per-run DNS cache to the SPF evaluator's resolver
// interface.
//
// Going through the cache matters here more than anywhere else: recursive SPF
// evaluation is the only check that follows a graph, and include trees for
// common providers converge on the same handful of names. Querying directly
// would multiply an audit's traffic against third-party nameservers for no
// additional information.
type cacheResolver struct {
	cache *Cache
}

// TXT returns the TXT records at a name, treating absence as an empty set
// rather than an error so the evaluator can count it as a void lookup.
func (c cacheResolver) TXT(ctx context.Context, name string) ([]string, error) {
	records, _, err := c.cache.LookupTXT(ctx, name)
	if err != nil {
		if isAbsent(err) {
			return nil, nil
		}
		return nil, err
	}
	return records, nil
}

// HasRecords reports whether a name has records of the given kind.
//
// A failed lookup reports false rather than propagating the error: this
// distinguishes void lookups from resolvable ones, and a receiver evaluating
// the policy would treat an unanswered query as void too. Surfacing the error
// would abort the whole check over one unreachable include.
func (c cacheResolver) HasRecords(ctx context.Context, name, kind string) (bool, error) {
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	switch kind {
	case "mx":
		qtypes = []uint16{dns.TypeMX}
	case "ptr":
		qtypes = []uint16{dns.TypePTR}
	case "txt":
		qtypes = []uint16{dns.TypeTXT}
	}

	for _, qtype := range qtypes {
		msg, _, err := c.cache.Exchange(ctx, name, qtype)
		if err != nil {
			continue
		}
		if len(msg.Answer) > 0 {
			return true, nil
		}
	}
	return false, nil
}
