# Spec 009 – Findings Model and Structured Reporting

## Specification ID
`009-findings-and-reporting`

## Status
`Partially Implemented`

Implemented: the `pkg/finding` model (severity, confidence, evidence, catalogue,
result envelope, states and error codes), all five renderers in `pkg/report`,
the CLI reporting flags, semantic exit codes, and the `catalogue` and `explain`
commands. The SPF and DMARC checks emit findings; the remaining checks still
report records only and are converted as spec `011` lands.

## Summary
Introduces a first-class **finding** as the unit of output, replacing ad-hoc
strings printed with `fmt.Println`. Adds severity, stable identifiers,
remediation guidance and machine-readable renderers (JSON, NDJSON, CSV, SARIF),
plus `--fail-on` for pipeline gating.

This is the foundational change: specs `010`–`014` all depend on it.

## Motivation
`vantage` currently retrieves records but does not interpret them. `spf
example.com` prints the record and exits `0` whether the record ends in `-all`
or `+all`. The analyst supplies the judgement, so the output cannot be sorted,
thresholded, trended, ingested by a SIEM, or used to fail a build.

There is also no way to answer the question a CISO actually asks: *"how bad is
it, and what do I fix first?"*

## Core Types
New package `pkg/finding`.

```go
type Severity int // Info, Low, Medium, High, Critical

type Finding struct {
    ID          string            `json:"id"`           // e.g. "SURF-SPF-004"
    Title       string            `json:"title"`
    Severity    Severity          `json:"severity"`
    Confidence  Confidence        `json:"confidence"`   // Low | Medium | High
    Target      string            `json:"target"`       // domain or FQDN assessed
    Check       string            `json:"check"`        // "spf", "dmarc", ...
    Description string            `json:"description"`
    Evidence    []Evidence        `json:"evidence,omitempty"`
    Remediation string            `json:"remediation"`
    References  []string          `json:"references,omitempty"`
    Tags        []string          `json:"tags,omitempty"` // compliance mappings
    FirstSeen   time.Time         `json:"first_seen,omitempty"`
}

type Evidence struct {
    Kind   string `json:"kind"`   // "dns-record", "http-response", "computed"
    Name   string `json:"name"`   // query name, e.g. "_dmarc.example.com"
    Type   string `json:"type"`   // "TXT", "MX", ...
    Value  string `json:"value"`  // the observed data
    Source string `json:"source"` // resolver that answered
}
```

### Finding identifiers
IDs are **stable and permanent**: `SURF-<CHECK>-<NNN>`. Once published an ID is
never reassigned or given a different meaning; a retired check's ID is
tombstoned. Agents and ticketing systems may key on them.

The full catalogue lives in `pkg/finding/catalogue.go` as the single source of
truth for title, default severity, description, remediation and references.
`ValidateCatalogue` enforces the invariants and is asserted by a test: IDs must
be unique and well formed, the ID's check segment must agree with the `Check`
field, and every entry must carry a description, remediation guidance and at
least one reference.

Numbers are allocated by the specification that defines the rule, so the
implemented set may be sparse (spec `011` reserves `SURF-SPF-006`, `007`, `009`
and `010`, which are not yet implemented). Only rules the tool can actually
perform appear in the catalogue, so `vantage catalogue` never advertises a
check that does not exist.

### Severity assignment
Severity is a property of the **catalogue entry**, adjusted at runtime only when
context justifies it (e.g. a missing SPF record is `High` for a domain with MX
records, `Low` for one with a null MX). Any adjustment must be recorded in
`Description`.

## Result Envelope
Every structured render emits one envelope, never interleaved fragments:

```json
{
  "schema_version": "1.0",
  "tool": { "name": "vantage", "version": "v1.4.0" },
  "started_at": "2026-08-02T09:15:00Z",
  "finished_at": "2026-08-02T09:15:04Z",
  "resolvers": ["1.1.1.1:53"],
  "targets": ["example.com"],
  "summary": { "critical": 0, "high": 2, "medium": 1, "low": 0, "info": 5 },
  "findings": [ ... ],
  "records": { "spf": "v=spf1 include:_spf.example.com ~all" },
  "errors": [ { "check": "mtasts", "message": "error: not found" } ]
}
```

- `records` preserves today's raw-retrieval behaviour so no information is lost.
- `errors` is non-fatal: one failed check never suppresses the others.
- `schema_version` follows semver; additive changes bump the minor component.

## Output Formats
Global flag `--format` (alias `-o`):

| Value | Behaviour |
|---|---|
| `text` | **Default.** Human-readable, backwards compatible for single-record commands |
| `json` | The envelope above, pretty-printed |
| `ndjson` | One finding per line; envelope metadata emitted as a leading `{"kind":"meta"}` record. Suitable for streaming and bulk runs |
| `csv` | Flattened findings, one row per finding |
| `sarif` | SARIF 2.1.0 for GitHub code scanning and DefectDojo |

Additional flags: `--severity <min>` (filter), `--fields a,b,c` (project a
subset, for token economy), `--no-color`, `--quiet`.

### Backwards compatibility
With `--format text` (the default) the existing single-purpose commands print
exactly what they print today — the record, nothing more — so existing scripts
are unaffected. Findings are shown only when `--findings` is passed, or
implicitly by the `audit` command (spec `010`).

### Catalogue access
`vantage catalogue [--check spf]` lists every finding the tool can raise, and
`vantage explain <id>` expands one entry. Both honour `--format json`.

Publishing the catalogue is what allows a consumer — human or automated — to
resolve a finding ID to reviewed, cited guidance rather than composing security
advice of its own.

## Exit Codes
| Code | Meaning |
|---|---|
| 0 | Completed; no finding met the `--fail-on` threshold |
| 1 | Runtime error (all resolvers unreachable, I/O failure) |
| 2 | Usage error (bad flag, missing argument) |
| 3 | Completed; at least one finding met or exceeded `--fail-on` |
| 4 | Completed, but one or more checks errored (partial result) |

`--fail-on <severity>` defaults to `off`. Exit code `3` is what a CI gate or an
agent keys on; it is deliberately distinct from `1` so that "the tool broke" and
"the domain is misconfigured" are never conflated.

## Compliance Tagging
`Tags` carries control mappings so output is directly reportable:
`ncsc-mailcheck`, `cis-controls`, `nist-800-81`, `pci-dss`. Mapping tables live
alongside the catalogue and are covered by tests.

## Requirements
1. `pkg/finding` MUST NOT import `pkg/scanner` (dependency flows one way).
2. Renderers MUST be deterministic — findings sorted by severity descending,
   then check, then ID — so output diffs cleanly (prerequisite for spec `013`).
3. Every catalogue entry MUST have non-empty remediation text and at least one
   reference.
4. Structured formats MUST write to stdout only; progress and diagnostics go to
   stderr, so `vantage ... -o json > out.json` is always valid JSON.
5. Findings MUST carry evidence sufficient to reproduce the conclusion without
   re-running the tool.

## Testing
- Golden-file tests per renderer.
- Catalogue integrity test (unique IDs, mandatory fields).
- SARIF output validated against the published JSON schema.
- Round-trip test: JSON envelope unmarshals into the same in-memory result.

## References
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [NCSC Mail Check](https://www.ncsc.gov.uk/information/mailcheck)
