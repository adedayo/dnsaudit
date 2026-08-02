# Spec 004 – CAA Record Inspection

## Specification ID
`004-caa`

## Title
Certification Authority Authorization (CAA) Record Audit

## Status
`Implemented`

## Summary
Queries DNS Certification Authority Authorization (CAA) records for a domain.
CAA records declare which certificate authorities are permitted to issue TLS
certificates for that domain. Missing CAA records allow any trusted CA to issue
a certificate, dramatically widening the attack surface.

## Motivation
From a CISO perspective, verifying CAA records helps:
- Prevent rogue or mis-issued certificates from untrusted CAs.
- Enforce the principle of least privilege for certificate issuance.
- Detect domains without CAA protection that could be exploited via CA compromise.

## Input
| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| domain    | string | yes      | Fully-qualified domain name to inspect |

## Output
A list of CAA record strings, one per line, in the format:
```
<flags> <tag> <value>
```

### Tags
| Tag       | Meaning                                             |
|-----------|-----------------------------------------------------|
| `issue`   | Permits the named CA to issue end-entity certs      |
| `issuewild` | Permits the named CA to issue wildcard certs      |
| `iodef`   | URL to report CA policy violations                  |

### Example
```
0 issue letsencrypt.org
0 issuewild ;
0 iodef mailto:certs@example.com
```

## Error Cases
| Condition               | Error message          |
|-------------------------|------------------------|
| No CAA records found    | `error: not found`     |
| DNS query failure       | `error: dns query failed: <cause>` |

## CLI Usage
```
dnsaudit caa example.com
```

## References
- [RFC 8659 – DNS CAA Resource Record](https://tools.ietf.org/html/rfc8659)
