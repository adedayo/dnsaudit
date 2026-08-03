# Spec 007 – DMARC Policy and Reporting URIs

## Specification ID
`007-dmarc-reporting`

## Status
`Implemented`

## Summary
Reports the effective DMARC policy together with the aggregate (`rua`) and
forensic (`ruf`) reporting destinations for a domain.

## Functions
- `scanner.LookupDMARC(ctx, domain) (string, error)` – normalised policy.
- `scanner.ParseDMARCReporting(ctx, domain) (rua, ruf []string, err error)`.

Both read TXT records at `_dmarc.<domain>` and only consider records prefixed
with `v=DMARC1`. Tag values are returned with the `rua=`/`ruf=` prefix stripped
(the `mailto:` scheme is preserved). The policy is lower-cased; unrecognised
values are passed through verbatim.

## Behaviour
The `dmarc-report` CLI tolerates partial failure: if the policy lookup succeeds
but reporting parsing fails, the policy is still printed and RUA/RUF show
`(none)`. An error is returned only when **both** fail.

## Error Cases
| Condition                       | Error message      |
|---------------------------------|--------------------|
| No DMARC record / no `p=` tag   | `error: not found` |
| Neither `rua` nor `ruf` present | `error: not found` |

## CLI
```
vantage dmarc example.com
vantage dmarc-report example.com
```
Output of `dmarc-report`:
```
Policy : quarantine
RUA    : mailto:agg@example.com
RUF    : (none)
```

## Backwards Compatibility
`vantage.LookupDMARC` in `pkg/dmarc.go` returns the **raw** DMARC record and is
retained unchanged for existing library consumers.

## References
- [RFC 7489 – DMARC](https://tools.ietf.org/html/rfc7489)
