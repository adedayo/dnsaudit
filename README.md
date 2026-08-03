[![License](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](LICENSE)
[![golangci-lint](https://github.com/adedayo/dnsaudit/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/adedayo/dnsaudit/actions/workflows/golangci-lint.yml)
[![build](https://github.com/adedayo/dnsaudit/actions/workflows/build.yml/badge.svg)](https://github.com/adedayo/dnsaudit/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/tag/adedayo/dnsaudit?label=release)](https://github.com/adedayo/dnsaudit/releases)

# DNS Audit

`dnsaudit` is a set of utilities for auditing security posture by interrogating
the DNS. It provides both a command-line interface and a reusable Go library
(`github.com/adedayo/dnsaudit/pkg/scanner`).

It runs on **Linux, macOS and Windows** — resolver configuration is discovered in
a platform-native way with graceful fallbacks, so no `/etc/resolv.conf` is
required.

## Commands

| Command | Description |
|---|---|
| `spf <domain>` | Sender Policy Framework record |
| `dkim <domain> -s <selector>` | DKIM public key record |
| `dmarc <domain>` | Effective DMARC policy |
| `dmarc-report <domain>` | DMARC policy plus `rua`/`ruf` reporting URIs |
| `mtasts <domain>` | MTA-STS TXT record, plus the policy file when findings are requested (`--no-network` to skip) |
| `tlsrpt <domain>` | SMTP TLS Reporting (`_smtp._tls`) record |
| `bimi <domain>` | Brand Indicators for Message Identification (`default._bimi`) |
| `dnssec <domain>` | DNSKEY presence (`enabled` / `not found`) |
| `nssec <domain>` | NSEC/NSEC3 denial-of-existence records |
| `smtp-dane <domain>` | TLSA records at `_25._tcp` |
| `https-dane <domain>` | TLSA records at `_443._tcp` |
| `ssh-dane <domain>` | TLSA records at `_22._tcp` |
| `caa <domain>` | Certification Authority Authorization records, climbing the domain tree per RFC 8659 |
| `ptr <domain>` | Reverse DNS lookup |
| `dnsbl <domain> -b <zone>` | DNS blocklist reputation check |
| `public-suffix <domain>` | Public Suffix List validation |
| `catalogue` | List every finding dnsaudit can report |
| `explain <finding-id>` | Explain a finding and how to fix it |
| `version` | Version, commit, build date and platform (also `--version`) |

## Findings and reporting

By default a command retrieves and prints the record. Pass `--findings` — or any
structured output format — to assess it instead:

```sh
dnsaudit spf example.com                    # v=spf1 include:_spf.example.com ~all
dnsaudit spf example.com --findings         # prioritised findings with remediation
dnsaudit dmarc example.com -o json          # full result envelope
```

Findings carry a stable identifier, a severity, the evidence behind the
conclusion and reviewed remediation guidance:

```
LOW       DNSA-SPF-005  SPF record uses softfail (~all) rather than fail (-all)
          The record terminates in `~all`. Mail from unauthorised hosts is
          marked but generally still delivered...
          Evidence: example.com TXT = v=spf1 include:_spf.example.com ~all
          Fix: Once DMARC aggregate reports confirm all legitimate senders are
          covered, tighten the terminal mechanism to `-all`.
```

Look any identifier up without running an assessment:

```sh
dnsaudit catalogue --check spf
dnsaudit explain DNSA-SPF-004
```

### Output formats

| Flag | Purpose |
|---|---|
| `-o text` | Human-readable (default) |
| `-o json` | Complete result envelope |
| `-o ndjson` | One object per line; streams, and stays cheap in bulk |
| `-o csv` | Flattened findings |
| `-o sarif` | SARIF 2.1.0 for GitHub code scanning and similar |

| Flag | Purpose |
|---|---|
| `--severity <level>` | Only report findings at or above this level |
| `--fail-on <level>` | Exit 3 if anything reaches this level |
| `--fields a,b,c` | Restrict structured output to these fields |
| `--summary` | Counts and check states only |
| `--no-catalogue-text` | Omit prose; resolve it later with `explain` |

### Exit codes

Exit codes are a contract, so a caller never has to parse output to learn what
happened — and a resolver outage is never mistaken for a security finding:

| Code | Meaning |
|---|---|
| 0 | Completed; nothing met the `--fail-on` threshold |
| 1 | Runtime error — the tool could not do its job |
| 2 | Usage error — bad flag or missing argument |
| 3 | Completed; a finding met or exceeded `--fail-on` |
| 4 | Completed, but one or more checks failed (partial result) |

```sh
dnsaudit spf example.com --fail-on high -o sarif > results.sarif
```

### Absent versus unassessed

Structured output distinguishes `ok`, `not_found`, `not_checked` and
`check_failed`. "No record published" and "we could not tell" are different
statements, and conflating them would let a reader conclude a control is missing
when in truth it was never assessed.

## Network egress

Almost everything `dnsaudit` does is DNS. One check goes further: **MTA-STS
retrieves the policy file** over HTTPS from
`https://mta-sts.<domain>/.well-known/mta-sts.txt`, because the TXT record alone
proves nothing. A domain advertising a policy it does not actually serve has the
appearance of protection without the substance, and senders have nothing to
enforce.

That request is made to the target's own infrastructure, never to a third party.
Redirects are refused and the certificate is validated, both required by
RFC 8461 §3.2 — following a redirect would let whoever controls the hop rewrite
the policy being audited.

`--no-network` restricts a run to DNS. It does **not** silently drop MTA-STS:
the check still runs and still reports a missing policy, since that is visible
from the TXT record alone and is the most consequential finding. Only the
policy-dependent rules are skipped, and the retrieved policy is absent from the
evidence so the report never implies a document was inspected when it was not.

```sh
dnsaudit audit example.com --no-network   # DNS only
dnsaudit mtasts example.com --no-network  # TXT record only
```

Checks declare their egress, so `dnsaudit audit --list-checks` shows the blast
radius before you invoke anything.

## Choosing resolvers

By default `dnsaudit` discovers nameservers in this order:

1. The `--resolver` flag (repeatable).
2. The `DNSAUDIT_RESOLVERS` environment variable (comma-separated).
3. Platform-native configuration:
   - Linux / macOS / BSD: `/etc/resolv.conf`
   - Windows: `GetAdaptersAddresses` (IP Helper API)
4. Well-known public resolvers (Cloudflare, Google, Quad9).

Addresses may be given with or without a port; `53` is assumed.

```sh
dnsaudit caa example.com --resolver 1.1.1.1
dnsaudit spf example.com --resolver 8.8.8.8 --resolver 9.9.9.9
DNSAUDIT_RESOLVERS=1.1.1.1,8.8.8.8 dnsaudit dmarc example.com
```

Resolvers are tried in order, so one unreachable nameserver does not fail the
audit. Truncated UDP responses are automatically retried over TCP.

## Timeouts

Two budgets bound every lookup. The defaults favour **fast failover** — a dead
nameserver is abandoned after 2 seconds rather than stalling the audit.

| Budget | Scope | Default | Flag | Environment variable |
|---|---|---|---|---|
| Query | One attempt against one resolver | `2s` | `--query-timeout` | `DNSAUDIT_QUERY_TIMEOUT` |
| Total | The whole lookup, across all resolvers | `10s` | `--timeout` | `DNSAUDIT_TIMEOUT` |

If you are on a slow, lossy or high-latency link (satellite, VPN, Tor, filtered
networks) and want the tool to wait longer, raise either or both:

```sh
# Be more patient with each resolver
dnsaudit spf example.com --query-timeout 5s --timeout 30s

# Same, via the environment
DNSAUDIT_QUERY_TIMEOUT=5s DNSAUDIT_TIMEOUT=30s dnsaudit spf example.com

# Or fail over even faster on a flaky network
dnsaudit spf example.com --query-timeout 500ms
```

Precedence is flag → environment variable → default. A single attempt never
overruns the total budget, and a `context.Context` deadline shorter than the
total timeout always wins.

## Library

All scanner functions take a `context.Context` as their first argument and return
errors prefixed with `error:` (see the sentinel table in spec `002`).

```go
ctx := context.Background()

// Optional: pin the resolvers and timeouts used by the library.
dnsaudit.SetResolvers("1.1.1.1")
dnsaudit.SetQueryTimeout(5 * time.Second)  // wait longer per resolver
dnsaudit.SetTotalTimeout(30 * time.Second) // and longer overall

policy, err := scanner.LookupDMARC(ctx, "example.com")
```

Passing `0` (or any non-positive duration) to either setter restores the default.

## Specifications

Specifications live under [`openspec/changes/`](openspec/changes). See
[`openspec/ROADMAP.md`](openspec/ROADMAP.md) for sequencing.

## Development

```sh
go test ./... -cover
go vet ./...
GOOS=windows go build ./...
```

### Pre-release verification

`pre-release.sh` runs the full local quality gate — module tidiness, `gofmt`,
`go vet`, `golangci-lint`, tests with the race detector and coverage,
cross-platform builds for Linux/macOS/Windows (amd64 and arm64), and an offline
CLI smoke test:

```sh
./pre-release.sh
```

| Variable | Effect |
|---|---|
| `SKIP_LINT=1` | Skip golangci-lint (not recommended) |
| `SKIP_RACE=1` | Skip the race detector |
| `AUTO_INSTALL=1` | Install golangci-lint if missing |
| `MIN_COVERAGE=40` | Fail if total coverage drops below the given percentage |

golangci-lint is configured in [`.golangci.yml`](.golangci.yml); install it with
`brew install golangci-lint` or:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

[GoReleaser](https://goreleaser.com) is optional but recommended — `pre-release.sh`
validates [`.goreleaser.yml`](.goreleaser.yml) when it is on `PATH`:

```sh
go install github.com/goreleaser/goreleaser/v2@latest
```

### Releasing

`release.sh` runs `pre-release.sh` first and **only** commits, tags and pushes if
every check passes.

```sh
./release.sh patch      # bump the patch component of the latest tag
./release.sh minor
./release.sh major
./release.sh v1.2.3     # or name the version explicitly

DRY_RUN=1 ./release.sh patch    # show what would happen, change nothing
```

It refuses to run if the tag already exists locally or on the remote, and if the
working tree is dirty (unless `ALLOW_DIRTY=1`, which folds the changes into the
release commit). The tag is annotated with the commit subjects since the previous
release, and publication is handled by `goreleaser`, then `gh`, then CI —
whichever is available first.

Pushing a `vX.Y.Z` tag triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which runs the
test suite and then GoReleaser. Each release ships:

- Prebuilt, statically linked binaries for linux, darwin and windows on both
  `amd64` and `arm64` (`tar.gz`, or `zip` on Windows).
- A `checksums.txt` file with SHA-256 digests of every archive.
- An SBOM per archive, generated with [syft](https://github.com/anchore/syft).
- Version, commit and build date baked into the binary — check with
  `dnsaudit version`.

Local `goreleaser` runs skip SBOM generation automatically when syft is not
installed.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
