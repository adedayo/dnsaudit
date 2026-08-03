# Roadmap

Specs `002`–`008` are implemented. Specs `009`–`014` are proposed and are
sequenced below, because the dependencies between them are strict.

## Dependency graph

```
009 findings & reporting  ──┬──> 010 aggregate audit ──┬──> 013 baseline & drift
                            │                          │
                            ├──> 011 deep analysis      └──> 014 agentic readiness
                            │
                            └──> 012 attack surface
```

`009` is foundational: it replaces string output with a findings model, so every
later spec depends on it. `014` depends on `010` because the capability manifest
and MCP tools are generated from the check registry.

## Phases

### Phase 1 — Foundation (`009`, `010`)
Refactor the 15 existing checks to return findings, add the renderers, add the
`audit` command and the check registry. No new detection capability, but this is
what makes everything after it possible — and it delivers immediate value
through `audit`, JSON output and `--fail-on`.

**Risk**: touches all 15 commands. Mitigated by keeping `--format text` output
byte-identical for the existing single-record commands, verified by golden files.

### Phase 2 — Depth (`011`)
Make the existing checks genuinely useful: SPF recursion and the ten-lookup
limit, DMARC organisational-domain fallback and external-destination
verification, DNSSEC chain validation, MTA-STS policy fetch, plus TLS-RPT, BIMI
and MX hygiene.

Highest security value per unit of effort, because the DNS plumbing already
exists.

**In progress.** DKIM key analysis (`DNSA-DKIM-001`–`006`) and TLS-RPT
(`DNSA-TLSRPT-001`–`002`) have landed, the latter as a new check and command.
Recursive SPF evaluation has also landed (`DNSA-SPF-006`, `007`, `009`, `010`):
includes and redirects are now followed through the resolver cache to count
DNS-querying mechanisms against the RFC 7208 ten-lookup limit, count void
lookups, detect include cycles and flag unusable include targets.

Building this surfaced two latent defects that were quietly corrupting results,
both now fixed and covered by tests. `pkg/dns.go` advertised no EDNS0 buffer, so
responses carrying large SPF trees failed to unpack and were misreported as an
unreachable resolver — disabling the check on the very domains it matters most
for. And `pkg/audit/cache.go` treated each 255-byte string of a long TXT record
as a separate record, which fragmented 2048-bit DKIM keys into false
`DNSA-DKIM-006` "malformed" findings and would have made one long SPF record
look like a duplicate.

Still outstanding: DNSSEC chain validation.

MX hygiene (`DNSA-MX-001`–`004`), CAA tree-climbing (`DNSA-CAA-001`–`005`),
BIMI (`DNSA-BIMI-001`–`003`) and the two remaining DMARC rules — organisational-
domain fallback (`DNSA-DMARC-009`) and external-destination verification
(`DNSA-DMARC-006`) — have now landed, taking the catalogue to 40 rules. BIMI is
a new check and command; CAA now climbs the domain tree and stops below the
public suffix, so a policy inherited from a parent is reported as inherited
rather than absent.

That work surfaced a third latent defect of the same family as the first two:
`pkg/dns.go` reported NXDOMAIN as a generic error rather than as absence, so
callers recorded "check failed" for a question the resolver had answered
conclusively. This disabled DMARC organisational-domain fallback in exactly the
common case, since a subdomain with no policy of its own usually does not
exist. SERVFAIL remains an error, as it should: the resolver genuinely could
not answer.

`DNSA-MX-005` (all exchangers within one ASN) is deferred to Phase 3, where
spec `012` introduces the network attribution it needs. Implementing it now
would mean inventing a proxy for an ASN and labelling it as one.

MTA-STS (`DNSA-MTASTS-001`–`008`) has now landed, taking the catalogue to 48
rules and leaving DNSSEC chain validation as the only outstanding work in this
phase. This is the first check to leave DNS: the policy file is fetched from
`https://mta-sts.<domain>/.well-known/mta-sts.txt`, with redirects refused and
the certificate validated per RFC 8461 §3.2. Verifying only the TXT record
would attest to an intention rather than a control, since a domain can
advertise a policy it does not serve.

That work surfaced a fourth defect of the same family — a definitive answer
misread as failure, only this time inverted. `--no-network` excluded every
check declaring HTTPS egress, so MTA-STS vanished entirely rather than
degrading. A domain publishing no policy at all was therefore reported clean in
exactly the mode a cautious operator would choose. The selection filter now
distinguishes *uses* egress from *cannot run without* it: a check that still
detects a missing control from DNS alone survives `--no-network` and skips only
its policy-dependent rules.

A related gap in the standalone `mtasts` command let it report a verdict drawn
from a policy file the operator never saw. Retrieved evidence is now recorded
alongside the DNS answers, and is absent under `--no-network` so the report
never implies a document was inspected when it was not.

### Phase 3 — Surface (`012`)
Subdomain takeover, zone transfer, delegation hygiene, wildcard detection,
CT enumeration, network attribution. Introduces an embedded fingerprint database
and optional third-party egress, so it needs the profile machinery from `010`.

### Phase 4 — Continuity (`013`)
Baselines, drift classification and suppression. Depends on the deterministic
ordering guaranteed by `009`.

### Phase 5 — Agents (`014`)
Capability manifest, JSON Schemas, finding catalogue commands, token-economy
flags and the MCP server. Deliberately last, because a manifest generated from
an incomplete registry would need rewriting at every earlier phase.

Note that several `014` requirements — stable exit codes, structured errors,
stdout/stderr discipline, evidence and confidence on every finding — are
**obligations on the earlier phases**, not deferred work. They are specified in
`009` and must be honoured as the foundation is built, otherwise Phase 5 becomes
a retrofit.

## Cross-cutting concerns

- **`cmd/` is at 0% test coverage.** Address during Phase 1, before the command
  surface grows further. *(Now at ~37%; `pkg/scanner` at ~41% is the weak spot.)*
- **Safety**: specs `012` and `014` add checks that query third-party
  infrastructure. The authorisation statement required by `012` should land in
  the README with the first such check, not afterwards.
- **Schema stability**: once `009` output ships, `schema_version` and finding IDs
  become a public contract. Treat them with the same care as the library API.
