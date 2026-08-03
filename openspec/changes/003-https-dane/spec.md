# Spec 003 – DANE TLSA Records (HTTPS, SSH, SMTP)

## Specification ID
`003-https-dane`

## Title
DANE TLSA Record Verification

## Status
`Implemented`

## Summary
Retrieves TLSA records to verify that a domain employs DNS-Based Authentication
of Named Entities (DANE). A single query routine (`lookupTLSA`) serves all three
services:

| Service | Query name      | Function                       | CLI          |
|---------|-----------------|--------------------------------|--------------|
| HTTPS   | `_443._tcp.<d>` | `LookupTLSAHTTPS`              | `https-dane` |
| SSH     | `_22._tcp.<d>`  | `LookupTLSASSH`                | `ssh-dane`   |
| SMTP    | `_25._tcp.<d>`  | `CheckDANE` / `LookupTLASSMTP` | `smtp-dane`  |

## Motivation
DANE detects whether services rely solely on CA-issued certificates (susceptible
to mis-issuance and rogue-CA attacks) or have supplementary DNS-level pinning.

## Input
| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| domain    | string | yes      | Fully-qualified domain name to inspect |

## Output
A `", "`-separated list of TLSA record strings:
```
<usage> <selector> <matching-type> <CERTIFICATE-HEX-UPPERCASE>
```

### Example
```
3 1 1 AABBCCDD
```

`dns.TLSA.Certificate` is already a hex string, so it is upper-cased directly
rather than re-encoded.

## Error Cases
| Condition             | Error message                      |
|-----------------------|------------------------------------|
| No TLSA records found | `error: not found`                 |
| DNS query failure     | `error: dns query failed: <cause>` |
| Non-success RCODE     | `error: dns response code <n>`     |

## CLI Usage
```
vantage https-dane example.com
vantage ssh-dane example.com
vantage smtp-dane example.com
```

## Testing
`LookupTLSAHTTPSWithServer`, `LookupTLSASSHWithServer` and
`LookupTLASSMTPWithServer` delegate to the shared `lookupTLSAWithServer` helper
and are exercised against a local mock DNS server.

## References
- [RFC 7671 – DANE Protocol](https://tools.ietf.org/html/rfc7671)
- [RFC 6698 – TLSA Resource Record](https://tools.ietf.org/html/rfc6698)
