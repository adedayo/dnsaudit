package vantage

import (
	"context"
	"fmt"
	"strings"
)

// LookupDMARC obtains the DMARC record of a domain.
// See https://tools.ietf.org/html/rfc7489
func LookupDMARC(ctx context.Context, domain string) (dmarc string, err error) {
	txts, err := LookupTXT(ctx, fmt.Sprintf("_dmarc.%s", domain))
	if err == nil {
		for _, txt := range txts {
			txt = strings.TrimSpace(txt)
			if strings.HasPrefix(txt, "v=DMARC1") {
				return txt, nil
			}
		}
	}
	return "", fmt.Errorf("no DMARC record found on %s", domain)
}
