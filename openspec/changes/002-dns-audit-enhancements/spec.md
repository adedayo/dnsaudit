# Specification: DNS Audit Enhancements for Trawl

## Goal
Enable Trawl to perform a comprehensive email security posture audit by extending the existing `dnsaudit` functionality. The enhancements will provide parsed DMARC policies, MTA‑STS detection, DNSSEC validation, DANE lookup, robust error handling, and a reusable Go library API.

## Background
The original `dnsaudit` repository supplies basic DNS look‑ups (SPF, DKIM, DMARC) and a CLI. In Trawl we have integrated a thin scanner based on `github.com/miekg/dns`, but several capabilities are still missing, causing inaccurate UI displays (e.g., DMARC policy shown as **WEAK (NONE)**) and limited extensibility.

## Functional Requirements
1. **DMARC Parsing**
   - Extract the `p=` tag from the DMARC TXT record and normalise it to one of `reject`, `quarantine`, `none`.
   - Expose the parsed policy via `store.EmailPosture.DMARCPolicy`.
2. **MTA‑STS Detection**
   - Perform a TXT lookup for `_mta-sts.<domain>`.
   - Return the raw value (or an empty string if not found).
3. **DNSSEC Validation**
   - Query `DNSKEY` records for the domain using `github.com/miekg/dns`.
   - Return `enabled` when at least one DNSKEY is present and the response is successful, otherwise `not found`.
4. **DANE Lookup**
   - Retrieve TLSA records for the SMTP service (`_25._tcp.<domain>`).
   - Return a comma‑separated list of formatted TLSA records (`usage selector matchingType certificate`).
5. **Library API**
   - Refactor the core lookup functions into a reusable package `pkg/scanner` exposing:
     - `LookupSPF(domain string) (string, error)`
     - `LookupDKIM(domain, selector string) (string, error)`
     - `LookupDMARC(domain string) (string, error)`
     - `CheckMTASts(domain string) (string, error)`
     - `CheckDNSSEC(domain string) (string, error)`
     - `CheckDANE(domain string) (string, error)`
6. **Error Normalisation**
   - All functions must return errors prefixed with `error:` and a `not found` sentinel when appropriate.
7. **Context Propagation**
   - Each API call receives a `context.Context` with a timeout (default 15 s) and respects cancellation.
8. **Testing**
   - Add unit tests for each function using a mock DNS server or pre‑recorded fixtures.
9. **Documentation**
   - Provide GoDoc comments for all exported functions and a README explaining usage.

## Non‑Functional Requirements
- Use only `github.com/miekg/dns` for DNS queries (no `net.LookupTXT`).
- Keep the public API stable for future extensions.
- Ensure the implementation does not increase the overall scan latency beyond 2 seconds per domain.

## Acceptance Criteria
- UI shows the correct DMARC badge (`STRICT (REJECT)`, `QUARANTINE`, or `WEAK (NONE)`).
- New fields appear in the `EmailPosture` model and are persisted correctly.
- All unit tests pass (`go test ./...`).
- Documentation builds without lint errors.
- No regression of existing SPF/DKIM functionality.

## OpenSpec Metadata
- Change ID: `002-dns-audit-enhancements`
- Owner: `@dayo`
- Target Version: `v0.2.0`
- Status: `proposed`

---
*This spec is stored under `openspec/changes/002-dns-audit-enhancements/spec.md` and is ready for implementation.*
