# Spec 003 – DANE for HTTPS (TLSA _443._tcp)

## Specification ID
`003-https-dane`

## Title
DANE TLSA Record Verification for HTTPS Services

## Status
`Implemented`

## Summary
Retrieves TLSA records published at `_443._tcp.<domain>` to verify that the
domain employs DNS-Based Authentication of Named Entities (DANE) for its HTTPS
service. DANE allows TLS certificate pinning via DNS, removing the dependency on
the traditional certificate-authority (CA) hierarchy for HTTPS.

## Motivation
A CISO/security team can use DANE to detect whether web services rely solely on
CA-issued certificates (which are susceptible to mis-issuance and rogue CA
attacks) or have supplementary DNS-level pinning in place.

## Input
| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| domain    | string | yes      | Fully-qualified domain name to inspect |

## Output
A comma-separated list of TLSA record strings in the format:
```
<usage> <selector> <matching-type> <certificate-hex>
```

### Example
```
3 1 1 AABBCCDD...
```

## Error Cases
| Condition                   | Error message                          |
|-----------------------------|----------------------------------------|
| No TLSA records found       | `error: not found`                     |
| DNS query failure           | `error: dns query failed: <cause>`     |
| resolv.conf unreadable      | `error: could not read resolv.conf: …` |

## CLI Usage
```
dnsaudit https-dane example.com
```

## References
- [RFC 7671 – DANE Protocol](https://tools.ietf.org/html/rfc7671)
- [RFC 6698 – TLSA Resource Record](https://tools.ietf.org/html/rfc6698)
