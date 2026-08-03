# Spec 011 – Deep Protocol Analysis

## Specification ID
`011-deep-protocol-analysis`

## Status
`Proposed`

## Summary
Upgrades the existing checks from record retrieval to standards-conformant
analysis, and adds the missing adjacent records (TLS-RPT, BIMI, MX hygiene).
Every rule below produces a catalogued finding per spec `009`.

## Motivation
Retrieving `v=spf1 ... ~all` tells an analyst nothing they could not get from
`dig`. The value `vantage` should add is knowing that the record exceeds the
RFC 7208 ten-lookup limit and therefore **fails open at receivers** — a
misconfiguration invisible to record retrieval and common in practice.

---

## SPF (RFC 7208)
Recursive evaluation of `include:`, `redirect=`, `a`, `mx`, `ptr`, `exists:`.

| ID | Condition | Severity |
|---|---|---|
| `SURF-SPF-001` | No SPF record and domain has MX or A records | High |
| `SURF-SPF-002` | Multiple SPF records (PermError at receivers) | High |
| `SURF-SPF-003` | Terminal `?all` or no terminal mechanism | Medium |
| `SURF-SPF-004` | Terminal `+all` — anyone may spoof the domain | Critical |
| `SURF-SPF-005` | Terminal `~all` (softfail) where `-all` is achievable | Low |
| `SURF-SPF-006` | DNS lookup count > 10 — receivers return PermError | High |
| `SURF-SPF-007` | Void lookup count > 2 | Medium |
| `SURF-SPF-008` | Deprecated `ptr:` mechanism present | Low |
| `SURF-SPF-009` | `include:` target does not resolve / has no SPF record | Medium |
| `SURF-SPF-010` | Record exceeds 255-octet string or 512-octet total | Low |
| `SURF-SPF-011` | Overly broad `ip4` range (shorter than /16) | Medium |

The evaluator MUST report the **computed lookup count** as evidence and MUST
guard against include loops (bounded depth, visited set).

## DKIM (RFC 6376)
- Selector remains explicit via `-s`, but when omitted the check probes a
  curated list of common selectors (`default`, `google`, `selector1`,
  `selector2`, `k1`, `s1`, `mail`, `dkim`, `mandrill`, `zoho`, …), sourced from
  the major mail providers. Absence of a probed selector is **not** a finding —
  only `Info` evidence — because enumeration is not proof of absence.
- Selectors discovered from DMARC aggregate reports or MX provider inference are
  preferred over blind probing.

| ID | Condition | Severity |
|---|---|---|
| `SURF-DKIM-001` | No DKIM key found for any known or supplied selector | Medium |
| `SURF-DKIM-002` | RSA key shorter than 1024 bits | High |
| `SURF-DKIM-003` | RSA key exactly 1024 bits (below current guidance) | Medium |
| `SURF-DKIM-004` | Revoked key — empty `p=` | Medium |
| `SURF-DKIM-005` | Test mode `t=y` in production | Low |
| `SURF-DKIM-006` | Malformed key record / unparseable base64 | Medium |

## DMARC (RFC 7489)
- Organisational-domain fallback: a subdomain with no record inherits the
  organisational domain's policy, computed via the Public Suffix List.
- Full tag parsing: `p`, `sp`, `pct`, `adkim`, `aspf`, `fo`, `ri`, `rua`, `ruf`.
- **External destination verification**: when `rua`/`ruf` point outside the
  domain, verify the authorisation record at
  `<domain>._report._dmarc.<destination>`. Without it the destination silently
  discards reports — a very common and entirely invisible failure.

| ID | Condition | Severity |
|---|---|---|
| `SURF-DMARC-001` | No DMARC record | High |
| `SURF-DMARC-002` | `p=none` — monitoring only, no enforcement | Medium |
| `SURF-DMARC-003` | `pct` < 100 with an enforcing policy | Low |
| `SURF-DMARC-004` | `sp=none` while `p` enforces — subdomains unprotected | Medium |
| `SURF-DMARC-005` | No `rua` — no visibility of authentication failures | Medium |
| `SURF-DMARC-006` | External `rua`/`ruf` lacking authorisation record | High |
| `SURF-DMARC-007` | Multiple DMARC records (policy ignored by receivers) | High |
| `SURF-DMARC-008` | Syntactically invalid record | High |
| `SURF-DMARC-009` | Policy inherited from organisational domain only | Info |

## DNSSEC
Extends beyond DNSKEY presence to chain-of-trust validation.

| ID | Condition | Severity |
|---|---|---|
| `SURF-DNSSEC-001` | Not enabled (no DNSKEY, no DS) | Medium |
| `SURF-DNSSEC-002` | DNSKEY present but no DS at parent — island of trust, not validated | High |
| `SURF-DNSSEC-003` | DS present but no matching DNSKEY — resolution fails for validators | Critical |
| `SURF-DNSSEC-004` | Weak algorithm (RSASHA1, algorithms 5/7, or RSA < 2048) | High |
| `SURF-DNSSEC-005` | RRSIG expires within 7 days | High |
| `SURF-DNSSEC-006` | RRSIG already expired | Critical |
| `SURF-DNSSEC-007` | NSEC (not NSEC3) permits zone walking | Low |
| `SURF-DNSSEC-008` | NSEC3 iteration count above RFC 9276 guidance | Low |

The check SHOULD also report whether the configured resolver sets the `AD` bit,
distinguishing "the zone is signed" from "my resolver validates".

## MTA-STS (RFC 8461)
The current check reads only the TXT record. This spec adds retrieval of the
policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.

| ID | Condition | Severity |
|---|---|---|
| `SURF-MTASTS-001` | No MTA-STS TXT record | Low |
| `SURF-MTASTS-002` | TXT record present but policy file unreachable — policy inert | High |
| `SURF-MTASTS-003` | `mode=testing` — no enforcement | Medium |
| `SURF-MTASTS-004` | `mode=none` | Medium |
| `SURF-MTASTS-005` | Policy `mx` patterns do not cover the published MX hosts | High |
| `SURF-MTASTS-006` | Policy `id` differs from the TXT `id` (stale cache risk) | Low |
| `SURF-MTASTS-007` | `max_age` below 86400 | Low |
| `SURF-MTASTS-008` | Policy served with an invalid certificate | High |

HTTP fetching MUST be opt-in via profile (`standard` and above), honour
`--timeout`, follow no redirects (per RFC 8461), and be skippable with
`--no-network` for DNS-only environments.

## TLS-RPT (RFC 8460) — new
| ID | Condition | Severity |
|---|---|---|
| `SURF-TLSRPT-001` | No `_smtp._tls` TXT record — no visibility of TLS failures | Low |
| `SURF-TLSRPT-002` | Malformed record or missing `rua` | Low |

## BIMI — new
| ID | Condition | Severity |
|---|---|---|
| `SURF-BIMI-001` | BIMI record present but DMARC not enforcing (prerequisite unmet) | Medium |
| `SURF-BIMI-002` | Logo URL not HTTPS or unreachable | Low |
| `SURF-BIMI-003` | `a=` VMC absent (required by some mailbox providers) | Info |

## CAA (RFC 8659)
| ID | Condition | Severity |
|---|---|---|
| `SURF-CAA-001` | No CAA record at the domain or any ancestor — any CA may issue | Medium |
| `SURF-CAA-002` | `issue` present without `issuewild` — wildcards unrestricted | Low |
| `SURF-CAA-003` | No `iodef` — no notification of unauthorised issuance attempts | Low |
| `SURF-CAA-004` | Unknown critical flag set on an unrecognised tag | Medium |
| `SURF-CAA-005` | Policy inherited from an ancestor domain | Info |

Tree-climbing MUST follow RFC 8659 §3 and report which label supplied the
policy.

## MX Hygiene — new
| ID | Condition | Severity |
|---|---|---|
| `SURF-MX-001` | MX host does not resolve | High |
| `SURF-MX-002` | MX points at a CNAME (prohibited by RFC 2181) | Low |
| `SURF-MX-003` | Non-mail domain lacks a null MX (`0 .`) per RFC 7505 | Low |
| `SURF-MX-004` | Single MX — no redundancy | Low |
| `SURF-MX-005` | All MX hosts within one ASN — concentration risk | Info |

## Requirements
1. Rules MUST cite the controlling RFC section in `References`.
2. Any check requiring egress beyond DNS MUST be individually skippable and
   MUST be excluded when `--no-network` is set.
3. Recursive evaluation MUST be depth- and time-bounded; loops produce a finding
   rather than a hang.
4. Where a conclusion depends on inference rather than observation, `Confidence`
   MUST be set below `High`.

## Testing
Table-driven tests per rule against a local mock DNS server, including the
adversarial cases: include loops, exactly-10 and 11-lookup SPF records, expired
RRSIGs, and MTA-STS policies that omit a published MX.
