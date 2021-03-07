package dnsaudit

import (
	"net"
)

//DNS record types: https://en.wikipedia.org/wiki/List_of_DNS_record_types

// LookupTXT returns the TXT records on a given domain
func LookupTXT(domain string) ([]string, error) {
	return net.LookupTXT(domain)

}
