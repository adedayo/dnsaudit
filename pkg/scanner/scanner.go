package scanner

import (
    "context"
    "fmt"
    "net"
    "strings"
    "time"

    "github.com/miekg/dns"
    d "github.com/adedayo/dnsaudit/pkg"
    "golang.org/x/net/publicsuffix"
)

// LookupSPF retrieves the SPF record for a domain and returns the raw record string.
func LookupSPF(ctx context.Context, domain string) (string, error) {
    txts, err := d.LookupTXT(ctx, domain)
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

// LookupDKIM retrieves the DKIM TXT record for a domain and selector.
func LookupDKIM(ctx context.Context, domain, selector string) (string, error) {
    name := fmt.Sprintf("%s._domainkey.%s", selector, domain)
    txts, err := d.LookupTXT(ctx, name)
    if err != nil {
        return "", err
    }
    if len(txts) > 0 {
        return txts[0], nil
    }
    return "", fmt.Errorf("error: not found")
}

// LookupDMARC parses the DMARC record and returns the effective policy (reject, quarantine, none).
func LookupDMARC(ctx context.Context, domain string) (string, error) {
    txts, err := d.LookupTXT(ctx, "_dmarc."+domain)
    if err != nil {
        return "", err
    }
    for _, txt := range txts {
        txt = strings.TrimSpace(txt)
        if strings.HasPrefix(txt, "v=DMARC1") {
            // Find p= tag
            parts := strings.Split(txt, ";")
            for _, p := range parts {
                p = strings.TrimSpace(p)
                if strings.HasPrefix(p, "p=") {
                    policy := strings.TrimPrefix(p, "p=")
                    switch strings.ToLower(policy) {
                    case "reject":
                        return "reject", nil
                    case "quarantine":
                        return "quarantine", nil
                    case "none":
                        return "none", nil
                    default:
                        return policy, nil
                    }
                }
            }
        }
    }
    return "", fmt.Errorf("error: not found")
}

// CheckMTASts returns the raw MTA‑STS TXT record if present.
func CheckMTASts(ctx context.Context, domain string) (string, error) {
    txts, err := d.LookupTXT(ctx, "_mta-sts."+domain)
    if err != nil {
        return "", err
    }
    if len(txts) > 0 {
        return txts[0], nil
    }
    return "", fmt.Errorf("error: not found")
}

// CheckDNSSEC queries DNSKEY records and returns "enabled" if any are found.
func CheckDNSSEC(ctx context.Context, domain string) (string, error) {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
    m.RecursionDesired = true
    client := new(dns.Client)
    client.Timeout = 15 * time.Second
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return "", fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    server := servers.Servers[0] + ":" + servers.Port
    resp, _, err := client.ExchangeContext(ctx, m, server)
    if err != nil {
        return "", fmt.Errorf("error: dns query failed: %w", err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return "", fmt.Errorf("error: dns response code %d", resp.Rcode)
    }
    for _, rr := range resp.Answer {
        if _, ok := rr.(*dns.DNSKEY); ok {
            return "enabled", nil
        }
    }
    return "not found", nil
}

// CheckDANE retrieves TLSA records for SMTP service and returns a comma‑separated list.
func CheckDANE(ctx context.Context, domain string) (string, error) {
    name := "_25._tcp." + domain
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(name), dns.TypeTLSA)
    m.RecursionDesired = true
    client := new(dns.Client)
    client.Timeout = 15 * time.Second
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return "", fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    server := servers.Servers[0] + ":" + servers.Port
    resp, _, err := client.ExchangeContext(ctx, m, server)
    if err != nil {
        return "", fmt.Errorf("error: dns query failed: %w", err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return "", fmt.Errorf("error: dns response code %d", resp.Rcode)
    }
    var records []string
    for _, rr := range resp.Answer {
        if tlsa, ok := rr.(*dns.TLSA); ok {
            rec := fmt.Sprintf("%d %d %d %s", tlsa.Usage, tlsa.Selector, tlsa.MatchingType, strings.ToUpper(fmt.Sprintf("%x", tlsa.Certificate)))
            records = append(records, rec)
        }
    }
    if len(records) == 0 {
        return "", fmt.Errorf("error: not found")
    }
    return strings.Join(records, ", "), nil
}

// LookupTLSAHTTPS retrieves TLSA records for HTTPS service (_443._tcp) and returns a comma‑separated list.
func LookupTLSAHTTPS(ctx context.Context, domain string) (string, error) {
    name := "_443._tcp." + domain
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(name), dns.TypeTLSA)
    m.RecursionDesired = true
    client := new(dns.Client)
    client.Timeout = 15 * time.Second
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return "", fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    server := servers.Servers[0] + ":" + servers.Port
    resp, _, err := client.ExchangeContext(ctx, m, server)
    if err != nil {
        return "", fmt.Errorf("error: dns query failed: %w", err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return "", fmt.Errorf("error: dns response code %d", resp.Rcode)
    }
    var records []string
    for _, rr := range resp.Answer {
        if tlsa, ok := rr.(*dns.TLSA); ok {
            rec := fmt.Sprintf("%d %d %d %s", tlsa.Usage, tlsa.Selector, tlsa.MatchingType, strings.ToUpper(fmt.Sprintf("%x", tlsa.Certificate)))
            records = append(records, rec)
        }
    }
    if len(records) == 0 {
        return "", fmt.Errorf("error: not found")
    }
    return strings.Join(records, ", "), nil
}

// LookupCAA retrieves CAA records for a domain and returns a slice of formatted strings.
func LookupCAA(ctx context.Context, domain string) ([]string, error) {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
    m.RecursionDesired = true
    client := new(dns.Client)
    client.Timeout = 15 * time.Second
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return nil, fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    server := servers.Servers[0] + ":" + servers.Port
    resp, _, err := client.ExchangeContext(ctx, m, server)
    if err != nil {
        return nil, fmt.Errorf("error: dns query failed: %w", err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return nil, fmt.Errorf("error: dns response code %d", resp.Rcode)
    }
    var records []string
    for _, rr := range resp.Answer {
        if caa, ok := rr.(*dns.CAA); ok {
            rec := fmt.Sprintf("%d %s %s", caa.Flag, caa.Tag, caa.Value)
            records = append(records, rec)
        }
    }
    if len(records) == 0 {
        return nil, fmt.Errorf("error: not found")
    }
    return records, nil
}

// ReverseLookupPTR resolves the domain to IPs, then performs a PTR lookup for the first IP.
func ReverseLookupPTR(ctx context.Context, domain string) (string, error) {
    ips, err := net.LookupIP(domain)
    if err != nil {
        return "", err
    }
    if len(ips) == 0 {
        return "", fmt.Errorf("error: no IPs found")
    }
    ptrName, err := dns.ReverseAddr(ips[0].String())
    if err != nil {
        return "", fmt.Errorf("error: unable to construct PTR name: %w", err)
    }
    m := new(dns.Msg)
    m.SetQuestion(ptrName, dns.TypePTR)
    m.RecursionDesired = true
    client := new(dns.Client)
    client.Timeout = 15 * time.Second
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return "", fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    server := servers.Servers[0] + ":" + servers.Port
    resp, _, err := client.ExchangeContext(ctx, m, server)
    if err != nil {
        return "", fmt.Errorf("error: dns query failed: %w", err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return "", fmt.Errorf("error: dns response code %d", resp.Rcode)
    }
    for _, rr := range resp.Answer {
        if ptr, ok := rr.(*dns.PTR); ok {
            return ptr.Ptr, nil
        }
    }
    return "", fmt.Errorf("error: not found")
}

// VerifyNSSEC checks for the presence of NSEC or NSEC3 records in the zone.
func VerifyNSSEC(ctx context.Context, domain string) (bool, error) {
    nsecMsg := new(dns.Msg)
    nsecMsg.SetQuestion(dns.Fqdn(domain), dns.TypeNSEC)
    nsecMsg.RecursionDesired = true
    nsec3Msg := new(dns.Msg)
    nsec3Msg.SetQuestion(dns.Fqdn(domain), dns.TypeNSEC3)
    nsec3Msg.RecursionDesired = true
    client := new(dns.Client)
    client.Timeout = 15 * time.Second
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return false, fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    server := servers.Servers[0] + ":" + servers.Port
    nsecResp, _, err := client.ExchangeContext(ctx, nsecMsg, server)
    if err == nil && nsecResp.Rcode == dns.RcodeSuccess && len(nsecResp.Answer) > 0 {
        return true, nil
    }
    nsec3Resp, _, err := client.ExchangeContext(ctx, nsec3Msg, server)
    if err == nil && nsec3Resp.Rcode == dns.RcodeSuccess && len(nsec3Resp.Answer) > 0 {
        return true, nil
    }
    return false, nil
}

// ParseDMARCReporting extracts rua and ruf URIs from the DMARC record.
func ParseDMARCReporting(ctx context.Context, domain string) (rua []string, ruf []string, err error) {
    txts, err := d.LookupTXT(ctx, "_dmarc."+domain)
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

// LookupTLSASSH retrieves TLSA records for SSH service (_22._tcp).
func LookupTLSASSH(ctx context.Context, domain string) (string, error) {
    name := "_22._tcp." + domain
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(name), dns.TypeTLSA)
    m.RecursionDesired = true
    client := new(dns.Client)
    client.Timeout = 15 * time.Second
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return "", fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    server := servers.Servers[0] + ":" + servers.Port
    resp, _, err := client.ExchangeContext(ctx, m, server)
    if err != nil {
        return "", fmt.Errorf("error: dns query failed: %w", err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return "", fmt.Errorf("error: dns response code %d", resp.Rcode)
    }
    var records []string
    for _, rr := range resp.Answer {
        if tlsa, ok := rr.(*dns.TLSA); ok {
            rec := fmt.Sprintf("%d %d %d %s", tlsa.Usage, tlsa.Selector, tlsa.MatchingType, strings.ToUpper(fmt.Sprintf("%x", tlsa.Certificate)))
            records = append(records, rec)
        }
    }
    if len(records) == 0 {
        return "", fmt.Errorf("error: not found")
    }
    return strings.Join(records, ", "), nil
}

// CheckDNSBL queries a DNSBL for the given domain's first IP.
func CheckDNSBL(ctx context.Context, domain, blocklist string) (bool, error) {
    ips, err := net.LookupIP(domain)
    if err != nil {
        return false, err
    }
    if len(ips) == 0 {
        return false, fmt.Errorf("error: no IPs found for domain")
    }
    var ip4 net.IP
    for _, ip := range ips {
        if ip.To4() != nil {
            ip4 = ip.To4()
            break
        }
    }
    if ip4 == nil {
        return false, fmt.Errorf("error: no IPv4 address for DNSBL check")
    }
    rev := fmt.Sprintf("%d.%d.%d.%d.%s", ip4[3], ip4[2], ip4[1], ip4[0], blocklist)
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(rev), dns.TypeA)
    m.RecursionDesired = true
    client := new(dns.Client)
    client.Timeout = 15 * time.Second
    servers, err := dns.ClientConfigFromFile("/etc/resolv.conf")
    if err != nil {
        return false, fmt.Errorf("error: could not read resolv.conf: %w", err)
    }
    server := servers.Servers[0] + ":" + servers.Port
    resp, _, err := client.ExchangeContext(ctx, m, server)
    if err != nil {
        return false, fmt.Errorf("error: dns query failed: %w", err)
    }
    if resp.Rcode != dns.RcodeSuccess {
        return false, nil // not listed
    }
    if len(resp.Answer) > 0 {
        return true, nil
    }
    return false, nil
}

// ValidatePublicSuffix checks whether the given domain is a registered public suffix.
// Returns true if the domain itself equals its own public suffix (i.e. it is a TLD/eTLD).
func ValidatePublicSuffix(_ context.Context, subdomain string) (bool, error) {
    ps, _ := publicsuffix.PublicSuffix(subdomain)
    return ps == subdomain, nil
}


// LookupTLASSMTP is an alias for CheckDANE (SMTP TLSA records).
func LookupTLASSMTP(ctx context.Context, domain string) (string, error) {
    return CheckDANE(ctx, domain)
}


