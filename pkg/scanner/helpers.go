package scanner

// helpers.go exposes server-parameterised variants of all scanner functions to
// enable unit testing against a local mock DNS server without modifying
// /etc/resolv.conf or relying on external DNS infrastructure.
//
// These functions mirror the public API but accept an explicit "server" address
// (e.g. "127.0.0.1:5353"). They are used by scanner_test.go and are NOT part
// of the public external API.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	d "github.com/adedayo/dnsaudit/pkg"
)

// lookupTXTWithServer is a server-parameterised version of d.LookupTXT.
func lookupTXTWithServer(ctx context.Context, name, server string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	m.RecursionDesired = true
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, fmt.Errorf("error: dns query failed: %w", err)
	}
	var txts []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			txts = append(txts, t.Txt...)
		}
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("error: not found")
	}
	return txts, nil
}

// LookupSPFWithServer is a test-friendly version of LookupSPF.
func LookupSPFWithServer(ctx context.Context, domain, server string) (string, error) {
	txts, err := lookupTXTWithServer(ctx, domain, server)
	if err != nil {
		return "", err
	}
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(txt, "v=spf1") {
			return txt, nil
		}
	}
	return "", fmt.Errorf("error: not found")
}

// LookupDMARCWithServer is a test-friendly version of LookupDMARC.
func LookupDMARCWithServer(ctx context.Context, domain, server string) (string, error) {
	txts, err := lookupTXTWithServer(ctx, "_dmarc."+domain, server)
	if err != nil {
		return "", err
	}
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(txt, "v=DMARC1") {
			parts := strings.Split(txt, ";")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "p=") {
					return strings.ToLower(strings.TrimPrefix(p, "p=")), nil
				}
			}
		}
	}
	return "", fmt.Errorf("error: not found")
}

// ParseDMARCReportingWithServer is a test-friendly version of ParseDMARCReporting.
func ParseDMARCReportingWithServer(ctx context.Context, domain, server string) (rua []string, ruf []string, err error) {
	txts, err := lookupTXTWithServer(ctx, "_dmarc."+domain, server)
	if err != nil {
		return nil, nil, err
	}
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(txt, "v=DMARC1") {
			parts := strings.Split(txt, ";")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "rua=") {
					rua = append(rua, strings.TrimPrefix(p, "rua="))
				} else if strings.HasPrefix(p, "ruf=") {
					ruf = append(ruf, strings.TrimPrefix(p, "ruf="))
				}
			}
		}
	}
	if len(rua) == 0 && len(ruf) == 0 {
		return nil, nil, fmt.Errorf("error: not found")
	}
	return rua, ruf, nil
}

// CheckMTAStsWithServer is a test-friendly version of CheckMTASts.
func CheckMTAStsWithServer(ctx context.Context, domain, server string) (string, error) {
	txts, err := lookupTXTWithServer(ctx, "_mta-sts."+domain, server)
	if err != nil {
		return "", err
	}
	if len(txts) > 0 {
		return txts[0], nil
	}
	return "", fmt.Errorf("error: not found")
}

// lookupTLSAWithServer queries TLSA records for an arbitrary name.
func lookupTLSAWithServer(ctx context.Context, name, server string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTLSA)
	m.RecursionDesired = true
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, m, server)
	if err != nil {
		return "", fmt.Errorf("error: dns query failed: %w", err)
	}
	var records []string
	for _, rr := range resp.Answer {
		if tlsa, ok := rr.(*dns.TLSA); ok {
			rec := fmt.Sprintf("%d %d %d %s",
				tlsa.Usage, tlsa.Selector, tlsa.MatchingType,
				strings.ToUpper(fmt.Sprintf("%x", tlsa.Certificate)))
			records = append(records, rec)
		}
	}
	if len(records) == 0 {
		return "", fmt.Errorf("error: not found")
	}
	return strings.Join(records, ", "), nil
}

// LookupTLSAHTTPSWithServer is a test-friendly version of LookupTLSAHTTPS.
func LookupTLSAHTTPSWithServer(ctx context.Context, domain, server string) (string, error) {
	return lookupTLSAWithServer(ctx, "_443._tcp."+domain, server)
}

// LookupTLSASSHWithServer is a test-friendly version of LookupTLSASSH.
func LookupTLSASSHWithServer(ctx context.Context, domain, server string) (string, error) {
	return lookupTLSAWithServer(ctx, "_22._tcp."+domain, server)
}

// LookupTLASSMTPWithServer is a test-friendly version of LookupTLASSMTP.
func LookupTLASSMTPWithServer(ctx context.Context, domain, server string) (string, error) {
	return lookupTLSAWithServer(ctx, "_25._tcp."+domain, server)
}

// LookupCAAWithServer is a test-friendly version of LookupCAA.
func LookupCAAWithServer(ctx context.Context, domain, server string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	m.RecursionDesired = true
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, fmt.Errorf("error: dns query failed: %w", err)
	}
	var records []string
	for _, rr := range resp.Answer {
		if caa, ok := rr.(*dns.CAA); ok {
			records = append(records, fmt.Sprintf("%d %s %s", caa.Flag, caa.Tag, caa.Value))
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("error: not found")
	}
	return records, nil
}

// VerifyNSSECWithServer is a test-friendly version of VerifyNSSEC.
func VerifyNSSECWithServer(ctx context.Context, domain, server string) (bool, error) {
	client := &dns.Client{Timeout: 5 * time.Second}
	for _, qtype := range []uint16{dns.TypeNSEC, dns.TypeNSEC3} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), qtype)
		msg.RecursionDesired = true
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err == nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// CheckDNSBLWithServer queries the DNSBL for a given net.IP using the provided server.
// This bypasses net.LookupIP so tests can control the IP under test.
func CheckDNSBLWithServer(ctx context.Context, ip4 net.IP, blocklist, server string) (bool, error) {
	ip4 = ip4.To4()
	if ip4 == nil {
		return false, fmt.Errorf("error: IPv4 required")
	}
	rev := fmt.Sprintf("%d.%d.%d.%d.%s", ip4[3], ip4[2], ip4[1], ip4[0], blocklist)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(rev), dns.TypeA)
	m.RecursionDesired = true
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, m, server)
	if err != nil {
		return false, fmt.Errorf("error: dns query failed: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false, nil
	}
	return len(resp.Answer) > 0, nil
}

// Ensure d import is used.
var _ = d.LookupTXT
