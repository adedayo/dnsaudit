# Spec 004 – CAA Records

## Specification ID
`004-caa`

## Title
Certification Authority Authorization (CAA) Record Retrieval

## Status
`Implemented`

## Summary
Retrieves the CAA records for a domain, revealing which certificate authorities
are authorised to issue certificates for it.

## Motivation
Without CAA records, any public CA may issue a certificate for the domain.
Publishing CAA constrains issuance and is a low-cost, high-value control.

## Input
| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| domain    | string | yes      | Fully-qualified domain name to inspect |

## Output
`scanner.LookupCAA` returns `[]string`, one entry per record, formatted as:
```
<flag> <tag> <value>
```

### Example
```
0 issue letsencrypt.org
0 iodef mailto:security@example.com
```

The CLI prints one record per line.

## Error Cases
| Condition            | Error message                      |
|----------------------|------------------------------------|
| No CAA records found | `error: not found`                 |
| DNS query failure    | `error: dns query failed: <cause>` |
| Non-success RCODE    | `error: dns response code <n>`     |

## CLI Usage
```
dnsaudit caa example.com
```

## Testing
`LookupCAAWithServer` is the server-parameterised variant used by the tests; it
shares the `formatCAA` implementation with the public API.

## References
- [RFC 8659 – DNS Certification Authority Authorization](https://tools.ietf.org/html/rfc8659)
