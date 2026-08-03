# Specification: DNS Audit Enhancements

## Specification ID
`002-dns-audit-enhancements`

## Status
`Implemented`

## Goal
Provide a comprehensive email/DNS security posture audit via a CLI and a
reusable Go library (`pkg/scanner`) covering SPF, DKIM, DMARC, MTA-STS, DNSSEC,
DANE, CAA, PTR, DNSBL, NSEC/NSEC3 and Public Suffix validation.

## Background
The original repository supplied basic DNS look-ups (SPF, DKIM, DMARC) and a
CLI. The scanner is implemented in `pkg/scanner` on top of `github.com/miekg/dns`
and shares a single query layer in `pkg/dns.go`.

## Functional Requirements

1. **DMARC Parsing**
   - `scanner.LookupDMARC` extracts the `p=` tag from `_dmarc.<domain>` and
     lower-cases it. Expected values: `reject`, `quarantine`, `none`; unknown
     values are returned verbatim.
   - `dnsaudit.LookupDMARC` (in `pkg/dmarc.go`) returns the **raw** DMARC record
     and is retained for backwards compatibility.
2. **DMARC Reporting** — see spec `007`.
3. **MTA-STS Detection**
   - TXT lookup of `_mta-sts.<domain>`; returns the first record or
     `error: not found`.
4. **DNSSEC Validation**
   - `scanner.CheckDNSSEC` queries `DNSKEY`. Returns the string `enabled` when at
     least one DNSKEY is present, otherwise the string `not found`. Note that
     `not found` is a **value**, not an error.
5. **Denial of Existence** — see spec `006`.
6. **DANE / TLSA** — see spec `003`.
7. **CAA** — see spec `004`.
8. **Reputation & Reverse DNS** — see spec `005`.
9. **Public Suffix** — see spec `006`.
10. **Platform-independent resolution** — see spec `008`.
11. **Library API** (`pkg/scanner`; every function takes `context.Context` first)
    ```go
    LookupSPF(ctx, domain) (string, error)
    LookupDKIM(ctx, domain, selector string) (string, error)
    LookupDMARC(ctx, domain) (string, error)
    ParseDMARCReporting(ctx, domain) (rua, ruf []string, err error)
    CheckMTASts(ctx, domain) (string, error)
    CheckDNSSEC(ctx, domain) (string, error)
    CheckDANE(ctx, domain) (string, error)
    LookupTLASSMTP(ctx, domain) (string, error)
    LookupTLSAHTTPS(ctx, domain) (string, error)
    LookupTLSASSH(ctx, domain) (string, error)
    LookupCAA(ctx, domain) ([]string, error)
    ReverseLookupPTR(ctx, domain) (string, error)
    VerifyNSSEC(ctx, domain) (bool, error)
    CheckDNSBL(ctx, domain, blocklist string) (bool, error)
    ValidatePublicSuffix(ctx, domain) (bool, error)
    ```
12. **Shared query layer** (`pkg`, package `dnsaudit`)
    ```go
    Resolvers() []string
    SetResolvers(servers ...string)
    ResetResolverCache()
    QueryTimeout() time.Duration          // per-resolver attempt budget
    TotalTimeout() time.Duration          // whole-lookup budget
    SetQueryTimeout(d time.Duration)
    SetTotalTimeout(d time.Duration)
    Exchange(ctx, name string, qtype uint16) (*dns.Msg, error)     // RCODE checked
    ExchangeRaw(ctx, name string, qtype uint16) (*dns.Msg, error)  // RCODE not checked
    ExchangeWithServer(ctx, server, name string, qtype uint16) (*dns.Msg, error)
    LookupTXT(ctx, domain) ([]string, error)
    LookupIP(ctx, host) ([]net.IP, error)
    ```
    - Queries are retried over TCP when a UDP response is truncated.
    - Queries fail over to the next configured resolver on transport errors or
      timeouts.
13. **Error Normalisation**
    - All errors are prefixed with `error:`.
    - Sentinels:
      | Sentinel | Meaning |
      |---|---|
      | `error: not found` | No matching record |
      | `error: dns query failed: <cause>` | Transport/resolution failure on all resolvers |
      | `error: dns response code <n>` | Non-success RCODE |
      | `error: no DNS resolvers available` | No resolver could be determined |
      | `error: context deadline exceeded` | Context expired before the query |
      | `error: invalid resolver address <addr>` | Malformed `--resolver` value |
    - The former `error: could not read resolv.conf: …` sentinel has been
      **removed**: a missing or unreadable resolver configuration is no longer
      fatal (see spec `008`).
14. **Context Propagation**
    - The lookup budget is the sooner of `dnsaudit.TotalTimeout()` (10 s by
      default) and the context deadline; each individual resolver attempt is
      bounded by `dnsaudit.QueryTimeout()` (2 s by default) so that failover is
      fast. Both are configurable — see spec `008`.
15. **CLI Commands**
    | Command | Function |
    |---|---|
    | `spf` | `LookupSPF` |
    | `dkim -s <selector>` | `LookupDKIM` |
    | `dmarc` | `LookupDMARC` |
    | `dmarc-report` | `LookupDMARC` + `ParseDMARCReporting` |
    | `mtasts` | `CheckMTASts` |
    | `dnssec` | `CheckDNSSEC` |
    | `nssec` | `VerifyNSSEC` |
    | `smtp-dane` | `LookupTLASSMTP` |
    | `https-dane` | `LookupTLSAHTTPS` |
    | `ssh-dane` | `LookupTLSASSH` |
    | `caa` | `LookupCAA` |
    | `ptr` | `ReverseLookupPTR` |
    | `dnsbl -b <zone>` | `CheckDNSBL` |
    | `public-suffix` | `ValidatePublicSuffix` |
    | `version` | Build metadata (also available as `--version`) |
    - Global flags: `--config`, `--resolver` (repeatable), `--query-timeout`,
      `--timeout`.
    - `version` reports the release version, commit, build date, Go version and
      `GOOS/GOARCH`. Values are injected at build time via `-ldflags` into
      `main.version`, `main.commit` and `main.date`, and fall back to the Go
      module build information embedded by `go install`.
    - Commands write records to stdout and errors to stderr, and return a
      non-zero exit code on failure.
16. **Testing**
    - `pkg/scanner/helpers.go` exposes `…WithServer` variants that accept an
      explicit resolver address, so `pkg/scanner` tests can run against a local
      mock DNS server. They delegate to `dnsaudit.ExchangeWithServer` and share
      all parsing/formatting logic with the public API. They are **not** part of
      the stable public API.
    - `CheckDNSBLWithServer` accepts a `net.IP` directly, bypassing address
      resolution.
    - `pkg/scanner/resolver_test.go` additionally exercises the public API by
      pointing `dnsaudit.SetResolvers` at a mock server.

## Non-Functional Requirements
- DNS queries use `github.com/miekg/dns` exclusively; the OS resolver
  (`net.LookupIP`) is no longer used, so `--resolver` is honoured everywhere and
  behaviour is identical on all platforms.
- The tool builds and runs on Linux, macOS and Windows with no build tags
  required by consumers.

## Acceptance Criteria
- CLI prints the correct DMARC policy for `reject` / `quarantine` / `none`.
- `go build ./...` succeeds for `GOOS=linux`, `GOOS=darwin` and `GOOS=windows`.
- All unit tests pass (`go test ./...`).
- `golangci-lint run ./...` is clean.
- No regression of existing SPF/DKIM functionality.

## OpenSpec Metadata
- Change ID: `002-dns-audit-enhancements`
- Owner: `@dayo`
- Target Version: `v0.2.0`
