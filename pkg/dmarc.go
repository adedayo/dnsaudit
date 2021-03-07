package dnsaudit

import (
	"fmt"
	"strings"
)

// LookupDMARC obtains the DMARC record of a domain
// https://tools.ietf.org/html/rfc7489
func LookupDMARC(domain string) (dmarc string, err error) {

	txts, err := LookupTXT(fmt.Sprintf("_dmarc.%s", domain))

	if err == nil {
		for _, txt := range txts {
			txt = strings.TrimSpace(txt)
			println(txt)
			if strings.HasPrefix(txt, "v=DMARC1") {
				fmt.Printf("FOUND %s", txt)
			}
		}
	}
	return
}
