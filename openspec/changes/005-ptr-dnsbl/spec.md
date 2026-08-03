# Spec 005 – Reverse DNS (PTR) and DNS Blocklist (DNSBL) Checks

## Specification ID
`005-ptr-dnsbl`

## Status
`Implemented`

## Summary
Two reputation-oriented checks:
- **PTR**: resolve the domain to IP addresses and reverse-look-up the first one.
- **DNSBL**: resolve the domain to an IPv4 address and query a DNS blocklist zone.

Both use `vantage.LookupIP` (not the OS resolver), so they honour `--resolver`
and behave identically on Linux, macOS and Windows — see spec `008`.

## PTR

### Function
`scanner.ReverseLookupPTR(ctx, domain) (string, error)`

### Behaviour
1. Resolve A/AAAA records via `vantage.LookupIP`.
2. Build the reverse name with `dns.ReverseAddr` for the **first** address.
3. Query `PTR` and return the first answer.

### Error Cases
| Condition                | Error message                                  |
|--------------------------|------------------------------------------------|
| Resolution failure       | `error: dns query failed: <cause>`             |
| No addresses resolved    | `error: no IPs found`                          |
| Reverse name build fails | `error: unable to construct PTR name: <cause>` |
| No PTR answer            | `error: not found`                             |

### CLI
```
vantage ptr example.com
```

## DNSBL

### Function
`scanner.CheckDNSBL(ctx, domain, blocklist) (bool, error)`

### Behaviour
1. Resolve the domain and select the first IPv4 address.
2. Query `A` for `<d>.<c>.<b>.<a>.<blocklist>`.
3. `true` when the RCODE is success **and** at least one answer is present.
4. NXDOMAIN (or any non-success RCODE) means *not listed* — returned as
   `(false, nil)`, **not** an error.

### Error Cases
| Condition                 | Error message                            |
|---------------------------|------------------------------------------|
| Resolution failure        | `error: dns query failed: <cause>`       |
| No addresses resolved     | `error: no IPs found for domain`         |
| No IPv4 address available | `error: no IPv4 address for DNSBL check` |

### CLI
```
vantage dnsbl example.com --blocklist zen.spamhaus.org
```
Default blocklist: `zen.spamhaus.org` (flag `-b/--blocklist`).

### Output
```
LISTED in zen.spamhaus.org: example.com
NOT LISTED in zen.spamhaus.org: example.com
```

## Testing
`CheckDNSBLWithServer(ctx, ip net.IP, blocklist, server string)` accepts an
address directly so the resolution step can be bypassed in unit tests.

## References
- [RFC 1035 – PTR records](https://tools.ietf.org/html/rfc1035)
- [RFC 5782 – DNS Blacklists and Whitelists](https://tools.ietf.org/html/rfc5782)
