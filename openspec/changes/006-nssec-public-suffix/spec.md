# Spec 006 – NSEC/NSEC3 Verification and Public Suffix Validation

## Specification ID
`006-nssec-public-suffix`

## Status
`Implemented`

## NSEC / NSEC3

### Function
`scanner.VerifyNSSEC(ctx, domain) (bool, error)`

### Behaviour
Queries `NSEC`, then `NSEC3`, for the domain via `vantage.ExchangeRaw`. Returns
`true` if either query succeeds (RCODE success) with at least one answer record;
otherwise `(false, nil)`. Transport errors on an individual query are treated as
"not present" rather than fatal, so the check never fails merely because the
zone does not publish these records.

### Error Cases
None: the function reports absence as `(false, nil)`.

### CLI
```
vantage nssec example.com
```
Output:
```
NSEC/NSEC3: present for example.com
NSEC/NSEC3: not found for example.com
```

## Public Suffix

### Function
`scanner.ValidatePublicSuffix(ctx, domain) (bool, error)`

### Behaviour
Uses the Mozilla Public Suffix List via `golang.org/x/net/publicsuffix`. Returns
`true` when the input **equals** its own public suffix (i.e. it is a TLD/eTLD).
No DNS query is performed; `ctx` is ignored.

### Examples
| Input         | Result  |
|---------------|---------|
| `com`         | `true`  |
| `example.com` | `false` |

### CLI
```
vantage public-suffix com
```
Output:
```
com is a public suffix
example.com is NOT a public suffix
```

## References
- [RFC 5155 – DNSSEC Hashed Authenticated Denial of Existence](https://tools.ietf.org/html/rfc5155)
- [Public Suffix List](https://publicsuffix.org/)
