# Spec 012 – Attack Surface Discovery

## Specification ID
`012-attack-surface`

## Status
`Proposed`

## Summary
Adds the externally exploitable exposures that are discoverable from DNS but
absent from the tool today: subdomain takeover, open zone transfer, nameserver
and delegation hygiene, wildcard records, Certificate Transparency enumeration
and network attribution.

## Motivation
Mail authentication is only half of DNS-derived risk. The other half is what an
attacker can *do* with the organisation's DNS: claim a dangling CNAME, download
the entire zone, or exploit a single point of failure in delegation. Subdomain
takeover in particular is the highest-impact, most frequently exploited class of
DNS misconfiguration and is fully detectable with the machinery already present.

---

## Subdomain Takeover
For each known host (supplied, enumerated per below, or read from a file),
resolve the CNAME chain and compare the terminal target against a fingerprint
database.

```go
type TakeoverFingerprint struct {
    Service      string   // "AWS S3", "GitHub Pages", "Azure Traefik Manager"
    CNAMEPattern []string // suffixes, e.g. ".s3.amazonaws.com"
    NXDOMAIN     bool     // vulnerable when the target does not resolve
    HTTPBody     []string // corroborating response fingerprints
    Status       string   // "vulnerable" | "edge-case" | "not-vulnerable"
    Reference    string
}
```

| ID | Condition | Severity |
|---|---|---|
| `SURF-TKO-001` | CNAME to a known service and target returns NXDOMAIN | Critical |
| `SURF-TKO-002` | CNAME to a known service with a claim-me HTTP fingerprint | Critical |
| `SURF-TKO-003` | CNAME to a known service, resolves, but unverified | Medium |
| `SURF-TKO-004` | Dangling CNAME to an unknown target (NXDOMAIN) | High |
| `SURF-TKO-005` | NS delegation to a nameserver that does not resolve | High |
| `SURF-TKO-006` | A/AAAA pointing into unallocated cloud space | Medium |

Requirements:
- The fingerprint database is **embedded data** (`pkg/takeover/fingerprints.json`)
  with a schema version and provenance, updatable without a code change.
- HTTP corroboration is optional (`standard`+ profiles) and MUST be a plain GET
  with no authentication and no attempt to claim the resource. `vantage`
  detects; it never exploits.
- Wildcard-aware: a domain with a wildcard record produces false NXDOMAIN
  reasoning, so the wildcard check below MUST run first and suppress or
  down-confidence takeover findings accordingly.

## Zone Transfer (AXFR)
Attempt AXFR against **each** authoritative nameserver.

| ID | Condition | Severity |
|---|---|---|
| `SURF-AXFR-001` | AXFR succeeds — entire zone disclosed | High |
| `SURF-AXFR-002` | AXFR partially succeeds or leaks SOA/record count | Medium |
| `SURF-AXFR-003` | IXFR permitted | Medium |

The transferred zone MUST NOT be written to disk by default; the finding records
the record count and a bounded sample as evidence. `--save-zone <dir>` opts in.
This check is enabled in `standard` and above and is clearly documented as
actively querying the target's nameservers.

## Nameserver and Delegation Hygiene
| ID | Condition | Severity |
|---|---|---|
| `SURF-NS-001` | Single authoritative nameserver — no redundancy | Medium |
| `SURF-NS-002` | All nameservers in one ASN / one provider | Low |
| `SURF-NS-003` | All nameservers in one /24 | Medium |
| `SURF-NS-004` | Parent and child NS sets disagree | Medium |
| `SURF-NS-005` | Lame delegation — NS does not answer authoritatively | High |
| `SURF-NS-006` | Missing glue for in-bailiwick nameservers | Medium |
| `SURF-NS-007` | Nameserver open to recursion — amplification vector | High |
| `SURF-NS-008` | SOA serial mismatch between nameservers | Low |
| `SURF-NS-009` | Nameserver domain expired or unregistered | Critical |

`SURF-NS-009` covers the takeover-by-expired-nameserver case, which is
catastrophic and cheap to detect.

## Wildcard Detection
Query three random, high-entropy labels. Consistent resolution indicates a
wildcard.

| ID | Condition | Severity |
|---|---|---|
| `SURF-WILD-001` | Wildcard A/AAAA record present | Info |
| `SURF-WILD-002` | Wildcard MX present | Low |
| `SURF-WILD-003` | Wildcard CNAME to a third-party service | Medium |

Results feed the takeover and enumeration checks as described above.

## Certificate Transparency Enumeration
Optional discovery of subdomains from CT logs, turning a single-domain audit
into an attack-surface inventory.

- Sources: `crt.sh` and the CT log API, behind an interface so sources can be
  added or replaced.
- Strictly opt-in (`surface` and `deep` profiles, or `--enumerate`), because it
  requires egress to a third party.
- Results are **inputs** to other checks, not findings in themselves, except:

| ID | Condition | Severity |
|---|---|---|
| `SURF-CT-001` | Certificates issued for hosts that no longer resolve | Info |
| `SURF-CT-002` | Internal-looking hostnames disclosed in public certificates | Medium |
| `SURF-CT-003` | Wildcard certificate covering the apex | Info |

`SURF-CT-002` uses a conservative keyword heuristic (`vpn`, `internal`, `dev`,
`staging`, `jira`, `admin`, …) and MUST be reported at `Medium` confidence.

`SURF-CT-001` and `SURF-CT-002` MUST report once per group rather than once per
name — all vanished names together, and internal-looking names grouped by the
keyword that matched — with every name retained as evidence. A large estate can
put hundreds of names in the logs, and one finding per name would bury the rest
of the report.

Caching to `~/.cache/vantage` with a documented TTL is required so repeat runs
do not hammer public services.

## Network Attribution
| ID | Condition | Severity |
|---|---|---|
| `SURF-NET-001` | Host resolves into a cloud provider outside the known estate | Info |
| `SURF-NET-002` | Host resolves to a private/reserved address (RFC 1918, CGNAT) — internal leakage | Medium |
| `SURF-NET-003` | Host resolves to an address in a different jurisdiction than expected | Info |

ASN and provider mapping uses embedded published cloud IP ranges; no external
lookup is required for `SURF-NET-002`.

## Ethical and Safety Requirements
1. All checks MUST be **passive or minimally interactive**. No brute force, no
   credential guessing, no exploitation, no resource claiming.
2. Checks that query the target's own infrastructure (AXFR, lame delegation,
   open recursion) MUST be documented as such and be individually skippable.
3. Rate limiting per spec `010` applies; the tool MUST NOT resemble an attack.
4. The README MUST state that users are responsible for having authority to
   assess the domains they target.

## Testing
- Fingerprint database schema and integrity tests.
- Mock DNS server tests for AXFR success/refusal, lame delegation, wildcard.
- Takeover logic tested against synthetic CNAME chains including the
  wildcard-induced false-positive case.
