# Spec 014 – Agentic AI Readiness

## Specification ID
`014-agentic-readiness`

## Status
`Proposed`

## Summary
Makes `vantage` a first-class tool for autonomous and semi-autonomous AI agents:
self-describing via a machine-readable capability manifest, deterministic and
unambiguous in its contracts, token-efficient in its output, safe by
construction, and directly consumable through a built-in Model Context Protocol
(MCP) server.

## Motivation
A CLI designed for humans is a poor tool for an agent. Humans tolerate prose
help text, interleaved progress output, ambiguous exit codes and error messages
that vary between releases; agents cannot. They must *discover* what the tool
can do, *understand* the shape of its output before parsing it, *distinguish*
"the tool failed" from "the domain is misconfigured", and *bound* the cost of
what they invoke.

Equally important, an agent acting on DNS assessment results needs the tool to
be honest about uncertainty. A finding presented without confidence or evidence
invites an agent to take confident action on a weak inference.

---

## 1. Capability Discovery

### `vantage capabilities`
Emits a JSON manifest describing the entire tool surface. This is the entry
point an agent reads first.

```json
{
  "schema_version": "1.0",
  "tool": { "name": "vantage", "version": "v1.4.0" },
  "description": "Assess the external security posture of a domain from DNS.",
  "safety": {
    "read_only": true,
    "mutates_target": false,
    "network_egress": ["dns", "https"],
    "requires_authorisation": true
  },
  "commands": [
    {
      "name": "audit",
      "summary": "Run all applicable checks against one or more domains.",
      "arguments": [
        { "name": "domain", "type": "string", "variadic": true,
          "required": true, "format": "hostname",
          "examples": ["example.com"] }
      ],
      "flags": [
        { "name": "profile", "type": "string",
          "enum": ["quick","standard","deep","email","surface"],
          "default": "standard",
          "description": "Breadth of assessment.",
          "cost_hint": { "quick": "low", "deep": "high" } }
      ],
      "output_schema": "vantage://schema/result",
      "exit_codes": { "0": "clean", "3": "findings at or above threshold" },
      "idempotent": true,
      "typical_duration_seconds": 6,
      "examples": [
        { "intent": "Check a domain's email spoofing risk",
          "command": ["audit","example.com","--profile","email","-o","json"] }
      ]
    }
  ],
  "checks": [
    { "name": "spf", "title": "Sender Policy Framework",
      "findings": ["SURF-SPF-001", "..."],
      "network": ["dns"], "profiles": ["quick","standard","deep","email"] }
  ],
  "finding_catalogue_uri": "vantage://catalogue"
}
```

Requirements:
- The manifest MUST be **generated from the same registry that drives execution**
  (spec `010`), never hand-maintained. A test asserts every registered command
  and check appears, so the manifest cannot drift from reality.
- `examples` MUST carry an `intent` in natural language, so an agent can match a
  user's goal to an invocation without guessing.
- `cost_hint` and `typical_duration_seconds` let an agent budget before running.

### `vantage schema [name]`
Emits JSON Schema (draft 2020-12) for `result`, `finding`, `baseline` and
`manifest`. Agents validate before parsing and detect version mismatch early.

### `vantage catalogue [--id SURF-SPF-004]`
Emits the finding catalogue — every ID with title, severity, description,
remediation, references and compliance tags. This lets an agent explain and
remediate a finding **without inventing guidance**, which is the single most
valuable property for reducing hallucinated security advice.

### `vantage explain <finding-id>`
Human- and agent-readable expansion of one catalogue entry, including a worked
remediation example.

---

## 2. Deterministic Contracts

1. **Exit codes are semantic and stable** (spec `009`): `0` clean, `1` tool
   failure, `2` usage error, `3` findings threshold met, `4` partial results.
   An agent must never need to parse text to learn whether a run succeeded.
2. **Errors are structured.** With `--format json`, failures emit a valid
   envelope containing an `errors` array — never a bare string on stderr.
   ```json
   { "schema_version":"1.0", "errors":[
     { "code":"RESOLVER_UNREACHABLE", "check":"spf",
       "message":"all resolvers failed", "retryable":true,
       "retry_after_seconds":5 }]}
   ```
   `code` values are stable enumerated identifiers; `message` is free text and
   MUST NOT be parsed. `retryable` tells an agent whether to try again rather
   than inferring it from wording.
3. **stdout carries data, stderr carries diagnostics.** Always. Progress
   indicators auto-disable when stdout is not a TTY.
4. **No interactivity.** No prompts, no pagers, no colour when not a TTY.
   `--yes` is unnecessary because no command is destructive.
5. **Stable ordering.** Deterministic sort (spec `009`) so repeated runs of an
   unchanged domain produce byte-identical output — this makes caching and
   change detection trivial for an agent.

---

## 3. Token Efficiency
Agent context is finite and expensive.

| Flag | Effect |
|---|---|
| `--summary` | Counts and grade only; omits evidence and descriptions |
| `--fields id,severity,title` | Project only the named fields |
| `--severity high` | Filter below a threshold at source |
| `--no-catalogue-text` | Omit description/remediation prose; return IDs only, resolvable later via `catalogue` |
| `-o ndjson` | Stream results so an agent can process incrementally and stop early |

The default JSON envelope MUST remain complete and self-contained; economy is
opt-in, so an agent is never silently deprived of context it did not know to
ask for.

`--summary` output is designed to fit comfortably in a few hundred tokens for a
typical domain, allowing an agent to triage a portfolio cheaply and drill into
only the interesting targets.

---

## 4. MCP Server Mode

### `vantage mcp`
Runs a Model Context Protocol server over stdio, exposing the tool natively to
MCP-capable agents without shelling out or parsing text.

**Tools exposed** (each mapping to a registry entry, generated not hand-written):
| Tool | Purpose |
|---|---|
| `dns_audit_domain` | Full assessment; params `domain`, `profile`, `checks` |
| `dns_check_email_security` | SPF/DKIM/DMARC/MTA-STS posture |
| `dns_check_attack_surface` | Takeover, AXFR, delegation (spec `012`) |
| `dns_explain_finding` | Catalogue lookup by ID |
| `dns_compare_baseline` | Drift against a supplied baseline (spec `013`) |
| `dns_lookup_record` | Single-record retrieval for targeted follow-up |

**Resources exposed**: `vantage://catalogue`, `vantage://schema/{name}`,
`vantage://capabilities`.

**Prompts exposed**: reusable templates such as
`assess_email_spoofing_risk(domain)` and `triage_portfolio(domains_file)` that
encode the correct sequence of tool calls, so an agent does not have to derive
methodology from first principles.

Requirements:
- Transport MUST be stdio by default; `--http` with an explicit bind address is
  opt-in and MUST default to loopback.
- Tool descriptions MUST state cost and safety properties, since these inform an
  agent's planning.
- Long-running calls MUST report progress via MCP progress notifications and
  honour cancellation through context propagation.
- The server MUST enforce the same rate limits and target caps as the CLI.

---

## 5. Safety Rails for Autonomous Use
An agent may invoke this tool without a human in the loop, so limits must be
enforced by the tool rather than by operator discipline.

| Control | Default | Purpose |
|---|---|---|
| `--max-targets` | 100 in MCP mode | Bound blast radius of a bad plan |
| `--query-rate` | 50/s per resolver | Never resemble an attack |
| `--timeout` | 10s (spec `008`) | Bound wall-clock cost |
| `--no-network` | off | Restrict to DNS only; disables HTTP-dependent checks |
| `--allow-domains` / `--deny-domains` | – | Restrict targets to an authorised scope |
| `VANTAGE_SCOPE_FILE` | – | Externally supplied authorised-scope list |

Requirements:
1. When a scope list is configured, targets outside it MUST be **refused**, with
   a structured error, not silently skipped — an agent must learn it exceeded
   its authority.
2. The manifest's `safety` block MUST accurately describe egress and mutation.
   Adding a check that mutates state or requires credentials MUST update it, and
   a test enforces consistency.
3. The tool MUST NOT persist findings to a remote service or telemetry endpoint.

---

## 6. Grounding and Honesty
These requirements exist to prevent an agent presenting confident security
advice that the evidence does not support.

1. Every finding MUST carry `Evidence` sufficient to justify it independently.
2. Every finding MUST carry `Confidence`; inference-based findings (common-selector
   DKIM probing, CT keyword heuristics, unverified takeover candidates) MUST NOT
   be `High`.
3. Absence of evidence MUST be distinguishable from evidence of absence. The
   result envelope separates `not_found` from `not_checked` from `check_failed`;
   an agent must never report "no DKIM configured" when the truth is "no selector
   was supplied".
4. Remediation text MUST come from the catalogue, so guidance is reviewed and
   version-controlled rather than generated at inference time.
5. `--explain` output MUST cite the controlling RFC or standard.

---

## Requirements Summary
1. Manifest, schemas and MCP tools MUST be generated from the execution registry.
2. Exit codes, error codes and finding IDs MUST be stable across releases;
   changes require a `schema_version` bump and a changelog entry.
3. `capabilities`, `schema` and `catalogue` MUST work offline and complete in
   well under a second.
4. All agent-facing surfaces MUST be covered by golden-file tests.

## Testing
- Manifest completeness test against the registry.
- JSON Schema validation of every renderer's output.
- MCP protocol conformance tests over stdio, including cancellation and progress.
- Scope-enforcement tests asserting refusal (not silent skip) for out-of-scope
  targets.
- Determinism test: two runs against a mock server produce identical bytes.

## References
- [Model Context Protocol](https://modelcontextprotocol.io)
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/release-notes)
