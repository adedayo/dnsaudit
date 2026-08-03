# Spec 010 – Aggregate `audit` Command and Bulk Assessment

## Specification ID
`010-aggregate-audit`

## Status
`Proposed`

## Summary
Adds a single `audit` command that runs every applicable check against one or
many domains concurrently and emits one consolidated result, plus bulk input,
profiles and concurrency controls.

## Motivation
Assessing one domain today means 15 separate invocations and manual
correlation. Assessing a portfolio of 200 domains is impractical. The aggregate
command is the primary entry point a CISO, an analyst or an AI agent will reach
for.

## CLI
```
dnsaudit audit example.com
dnsaudit audit example.com acme.co.uk --format json
dnsaudit audit --domains-file portfolio.txt --format ndjson --fail-on high
cat domains.txt | dnsaudit audit --stdin -o ndjson
```

### Flags
| Flag | Default | Purpose |
|---|---|---|
| `--profile` | `standard` | `quick`, `standard`, `deep`, `email`, `surface` |
| `--checks` | (all in profile) | Explicit allow-list, comma separated |
| `--skip-checks` | – | Deny-list, applied after `--checks` |
| `--domains-file` | – | One domain per line; `#` comments and blanks ignored |
| `--stdin` | `false` | Read targets from standard input |
| `--concurrency` | `8` | Domains assessed in parallel |
| `--check-concurrency` | `6` | Checks in flight per domain |
| `--max-targets` | `0` (unlimited) | Safety valve for agent/CI use |
| `--progress` | auto | Progress to stderr; auto-disabled when not a TTY |

### Profiles
| Profile | Contents |
|---|---|
| `quick` | SPF, DMARC, DNSSEC presence, CAA, MX — DNS only, no network egress beyond DNS |
| `standard` | `quick` + DKIM common selectors, MTA-STS policy fetch, TLS-RPT, NS hygiene, wildcard, zone transfer |
| `email` | Everything mail-related: SPF (recursive), DKIM, DMARC (full), MTA-STS, TLS-RPT, BIMI, MX hygiene |
| `surface` | Attack-surface discovery per spec `012`: CT enumeration, takeover, AXFR, delegation |
| `deep` | All checks, including those with external HTTP dependencies and enumeration |

Profiles are declared in data, not code, so adding a check does not require
editing profile logic.

## Execution Model
- A `Runner` orchestrates checks; each check implements:
  ```go
  type Check interface {
      Name() string
      Describe() Description        // for the capability manifest (spec 014)
      Run(ctx context.Context, t Target) ([]finding.Finding, error)
  }
  ```
- Checks are registered in `pkg/audit/registry.go`. Registration is the only
  step needed to expose a check to the CLI, profiles, the manifest and the MCP
  server.
- **Result sharing**: a per-run cache memoises DNS answers so that, for example,
  the MX lookup needed by SPF, DANE and mail-hygiene checks happens once. Cache
  key is `(qname, qtype)`; TTLs are respected within a run only.
- One check failing MUST NOT abort the run; it is recorded in `errors` and the
  process exits `4` unless a more severe code applies.
- The whole run honours `--timeout`; per-domain and per-check budgets derive
  from it as in spec `008`.

## Output
`--format text` renders a prioritised report:

```
example.com  ── 2 high, 1 medium, 5 info

HIGH    DNSA-SPF-004  SPF record permits all senders (+all)
        Evidence: v=spf1 include:_spf.example.com +all
        Fix: replace +all with -all once senders are enumerated.

HIGH    DNSA-TKO-001  Dangling CNAME to unclaimed S3 bucket
...

Posture: SPF ✓  DKIM ✓  DMARC ⚠ (p=none)  DNSSEC ✗  MTA-STS ✗  CAA ✓
```

Structured formats emit the spec `009` envelope, with `targets` holding every
domain assessed. For bulk runs `ndjson` is strongly preferred and the tool
SHOULD suggest it when `--format json` is used with more than 50 targets.

## Scoring
An optional posture grade (`A`–`F`) derived deterministically from weighted
severity counts, exposed as `summary.grade`. The algorithm MUST be documented
and versioned (`summary.grade_version`) — an ungrounded score that silently
changes between releases is worse than none, because trend lines become
meaningless.

## Requirements
1. Concurrency MUST be bounded and resolver-friendly: a global token bucket
   limits queries per second per resolver (`--query-rate`, default 50/s) to
   avoid the tool being mistaken for an attack or rate-limited mid-audit.
2. Bulk input MUST be validated and de-duplicated; invalid entries are reported
   as errors rather than aborting the run.
3. Memory use MUST be bounded for large portfolios — with `ndjson`, results
   stream rather than accumulating.
4. `audit` MUST be safe to run against third-party domains: it performs only
   passive queries plus, in `deep`, well-formed HTTPS GETs to documented
   well-known paths. No brute force, no credential use.

## Testing
- Runner tests with a mock registry: verify concurrency limits, error isolation,
  cache hit behaviour and deterministic ordering.
- Golden-file test for the text report.
- Bulk test with 1,000 synthetic targets asserting bounded memory and streaming.
