# Spec 008 – Platform-Independent Resolver Configuration

## Specification ID
`008-platform-independent-resolution`

## Status
`Implemented`

## Summary
Removes the previous hard dependency on `/etc/resolv.conf`, which made the tool
unusable on Windows and fragile in minimal containers. Resolver discovery is now
layered and platform native, so `dnsaudit` runs unchanged on **Linux, macOS and
Windows**.

## Motivation
Every query previously called `dns.ClientConfigFromFile("/etc/resolv.conf")` and
returned `error: could not read resolv.conf` when the file was absent. Windows
has no such file, so the tool was effectively POSIX-only. In addition, only the
first nameserver was ever used, so a single unreachable resolver failed the whole
audit.

## Resolution Order
`dnsaudit.Resolvers()` returns an ordered list of `host:port` addresses,
determined by the first source that yields a usable entry:

| # | Source | Notes |
|---|---|---|
| 1 | `dnsaudit.SetResolvers(...)` | Set by the `--resolver` CLI flag or by library callers |
| 2 | `DNSAUDIT_RESOLVERS` env var | Comma-separated list |
| 3 | Platform-native configuration | See below |
| 4 | `dnsaudit.FallbackResolvers` | Cloudflare, Google, Quad9 (incl. IPv6) |

### Platform-native configuration
| Platform | Mechanism | File |
|---|---|---|
| Linux, macOS, BSD, Android | `resolv.conf` parsing (`/etc/resolv.conf`, plus the Termux path) | `pkg/resolver_unix.go` (`//go:build !windows`) |
| Windows | `GetAdaptersAddresses` (IP Helper API) via `golang.org/x/sys/windows` | `pkg/resolver_windows.go` (`//go:build windows`) |

On Windows, adapters that are not operationally up and loopback adapters are
skipped, as are the reserved `fec0:0:0:ffff::1-3` site-local placeholder
addresses that Windows reports when no real resolver is configured.

## Address Normalisation
`normaliseServer` accepts and canonicalises:

| Input | Output |
|---|---|
| `1.1.1.1` | `1.1.1.1:53` |
| `8.8.8.8:5353` | `8.8.8.8:5353` |
| `2606:4700:4700::1111` | `[2606:4700:4700::1111]:53` |
| `[2606:4700:4700::1111]:53` | `[2606:4700:4700::1111]:53` |
| `resolver.example.com` | `resolver.example.com:53` |
| `""` | `error: empty resolver address` |

Duplicate and unparseable entries are discarded.

## Query Behaviour
- Resolvers are tried **in order**; a transport failure or timeout falls through
  to the next one. Only when all fail is `error: dns query failed: <cause>`
  returned.
- Iteration stops early if the caller's context is cancelled or expires.
- Truncated UDP responses are automatically retried over TCP.
- Discovery results are cached; `dnsaudit.ResetResolverCache()` forces a re-read
  for long-running processes whose network configuration changes.

## Timeouts

Two independent budgets bound every lookup, so that an unreachable nameserver is
abandoned quickly rather than stalling the whole audit:

| Budget | Scope | Default | Flag | Environment variable | Setter |
|---|---|---|---|---|---|
| Query | One attempt against one resolver | `2s` | `--query-timeout` | `DNSAUDIT_QUERY_TIMEOUT` | `SetQueryTimeout` |
| Total | The entire lookup, across all resolvers | `10s` | `--timeout` | `DNSAUDIT_TIMEOUT` | `SetTotalTimeout` |

Precedence for each budget is: setter/flag → environment variable → default. A
non-positive value passed to a setter restores the default. Environment values
are Go duration strings (`500ms`, `3s`, `1m`); unparseable or non-positive values
are ignored in favour of the default.

Rules:
- The effective budget is the **sooner** of the configured total timeout and the
  caller's `context.Context` deadline.
- A single attempt is given `min(QueryTimeout, remaining total budget)`, so the
  overall deadline is never overrun.
- Iteration stops as soon as the total budget is exhausted, even if resolvers
  remain untried.
- `ExchangeWithServer` targets one explicit resolver and therefore has no
  failover; it is granted the **full** budget rather than the shorter query
  timeout.
- `DefaultTimeout` is retained as a deprecated alias of `DefaultTotalTimeout`.

Users on slow, lossy or high-latency links (satellite, VPN, Tor, filtered
networks) should raise `--query-timeout`, and `--timeout` alongside it if many
resolvers are configured.

## Address Resolution
`dnsaudit.LookupIP` replaces `net.LookupIP` for the A/AAAA resolution performed
by the PTR and DNSBL checks. This means those checks also honour `--resolver`
and behave identically across platforms. IP literals are returned unchanged.

## CLI
```
dnsaudit caa example.com --resolver 1.1.1.1
dnsaudit ptr example.com --resolver 8.8.8.8 --resolver 9.9.9.9
DNSAUDIT_RESOLVERS=1.1.1.1,8.8.8.8 dnsaudit spf example.com

# Fail over sooner on a flaky network:
dnsaudit spf example.com --query-timeout 500ms

# Be more patient on a slow link:
dnsaudit spf example.com --query-timeout 5s --timeout 30s
DNSAUDIT_QUERY_TIMEOUT=5s DNSAUDIT_TIMEOUT=30s dnsaudit spf example.com
```

## Removed Error Case
`error: could not read resolv.conf: <cause>` no longer exists. Absence of a
system resolver configuration degrades to the public fallbacks instead of
failing.

## Acceptance Criteria
- `go build ./...` succeeds for `GOOS=windows`, `GOOS=linux` and `GOOS=darwin`.
- `Resolvers()` never returns an empty slice.
- Every returned address is already in normalised `host:port` form.
- The public scanner API can be driven entirely against a local mock DNS server
  by calling `SetResolvers`.
- A lookup whose first resolvers are blackholed still succeeds via a later
  resolver in well under the total budget.
- A lookup in which every resolver is unreachable fails within the total budget.

## References
- [GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)
- [RFC 1035 – Domain Names](https://tools.ietf.org/html/rfc1035)
