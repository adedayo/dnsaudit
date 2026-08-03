# Spec 013 – Baseline Snapshots and Drift Detection

## Specification ID
`013-baseline-and-drift`

## Status
`Proposed`

## Summary
Adds the ability to record a domain's DNS security posture as a signed snapshot
and to detect changes against it, turning `dnsaudit` from a point-in-time
assessment into continuous monitoring.

## Motivation
Unauthorised or unnoticed DNS change is a high-signal security indicator: a new
MX, a weakened SPF terminal, a removed CAA record or a changed nameserver may be
the first observable evidence of compromise, of a registrar account takeover, or
simply of a team shipping without review. A point-in-time report cannot surface
any of it. This is also the workflow most naturally scheduled in CI and most
naturally driven by an autonomous agent.

## CLI
```
dnsaudit baseline create example.com --out baselines/example.com.json
dnsaudit baseline create --domains-file portfolio.txt --out-dir baselines/
dnsaudit baseline diff example.com --baseline baselines/example.com.json
dnsaudit baseline verify baselines/example.com.json
dnsaudit audit example.com --baseline baselines/example.com.json --fail-on-drift
```

## Snapshot Format
```json
{
  "schema_version": "1.0",
  "created_at": "2026-08-02T09:15:00Z",
  "tool_version": "v1.4.0",
  "target": "example.com",
  "profile": "standard",
  "records": {
    "SPF":   [{ "name": "example.com", "value": "v=spf1 ... -all" }],
    "MX":    [{ "name": "example.com", "value": "10 mx1.example.com." }],
    "NS":    [ ... ],
    "DMARC": [ ... ],
    "CAA":   [ ... ],
    "DNSKEY":[ ... ]
  },
  "findings_digest": { "DNSA-DMARC-002": "accepted", "...": "..." },
  "digest": "sha256:…"
}
```

- Snapshots capture **records**, not findings, as the primary artefact: findings
  change as rules improve, records change only when the domain changes. A
  finding digest is stored alongside so rule-driven changes are distinguishable
  from domain-driven ones.
- TTLs and record ordering are normalised before hashing so that round-robin
  and TTL countdown do not register as drift.
- `digest` covers the normalised content, enabling tamper-evident storage and
  cheap equality checks.

## Drift Classification
| Class | Meaning | Default severity |
|---|---|---|
| `added` | Record present now, absent in baseline | varies |
| `removed` | Record absent now, present in baseline | varies |
| `modified` | Same name/type, different value | varies |
| `unchanged` | No difference | Info |

Severity is assigned by record class, because not all drift is equal:

| ID | Condition | Severity |
|---|---|---|
| `DNSA-DRIFT-001` | Nameserver (NS) set changed | High |
| `DNSA-DRIFT-002` | MX set changed | High |
| `DNSA-DRIFT-003` | SPF weakened (terminal moved toward `+all`, or senders added) | High |
| `DNSA-DRIFT-004` | DMARC policy weakened (`reject`→`quarantine`→`none`) | High |
| `DNSA-DRIFT-005` | CAA record removed or relaxed | Medium |
| `DNSA-DRIFT-006` | DNSKEY/DS changed — possible key rollover or compromise | High |
| `DNSA-DRIFT-007` | New subdomain observed | Info |
| `DNSA-DRIFT-008` | Posture improved (strengthened policy) | Info |
| `DNSA-DRIFT-009` | Any other monitored record changed | Low |

**Directionality matters**: the differ MUST understand that `p=reject` →
`p=none` is a weakening while the reverse is an improvement, and grade them
differently. A naive textual diff would report both identically and train
operators to ignore the output.

## Suppression and Accepted Risk
`.dnsaudit-ignore.yml` in the working directory (or `--ignore-file`):

```yaml
suppress:
  - id: DNSA-DMARC-002
    target: legacy.example.com
    reason: "Rollout to p=quarantine scheduled Q4; risk accepted by CISO."
    expires: 2026-12-31
```

- Suppressions MUST carry a reason; entries without one are rejected.
- `expires` is mandatory and MUST be in the future; expired suppressions
  reactivate the finding and raise `DNSA-META-001` (Low) so accepted risk cannot
  be quietly permanent.
- Suppressed findings still appear in structured output with
  `"suppressed": true`, so nothing is hidden from an auditor.

## Exit Codes
`--fail-on-drift` causes exit code `3` when any drift at or above the given
severity is detected, consistent with spec `009`.

## Requirements
1. Snapshot creation and diffing MUST be fully offline for the diff step — a
   baseline plus a fresh audit is sufficient, no stored credentials or service.
2. Normalisation MUST be deterministic and covered by tests, since false drift
   destroys trust in the signal faster than missing drift.
3. Schema evolution MUST be backwards compatible; the tool reads older snapshot
   versions and reports when a baseline predates a schema change.
4. Snapshots MUST be diff-friendly plain JSON so they can be committed to Git
   and reviewed in pull requests — this makes DNS change reviewable by the same
   process as code.

## Testing
- Round-trip and golden-file tests for snapshot creation.
- Normalisation tests: TTL countdown, round-robin reordering, case differences
  and trailing dots MUST NOT produce drift.
- Directionality tests for SPF and DMARC weakening versus strengthening.
- Suppression expiry tests.
