
[![License](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](LICENSE)
[![golangci-lint](https://github.com/adedayo/dnsaudit/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/adedayo/dnsaudit/actions/workflows/golangci-lint.yml)
[![Release](https://img.shields.io/github/v/tag/adedayo/dnsaudit?label=release)](https://github.com/adedayo/dnsaudit/releases)
Can 

# DNS Audit

dnsaudit is a set of utilities for auditing security posture by interrogating the DNS. It provides both a command‑line interface and a reusable Go library to query and interpret DNS records relevant to security posture, including:

- **SPF**: Retrieve the domain’s SPF policy.
- **DKIM**: Look up DKIM selectors.
- **DMARC**: Parse the DMARC record and expose the effective policy (reject, quarantine, none).
- **MTA‑STS**: Detect the presence of MTA‑STS TXT records.
- **DNSSEC**: Validate whether DNSSEC is enabled for a domain.
- **DANE**: Retrieve TLSA records for SMTP services.

The tool follows the OpenSpec specification defined in `openspec/changes/002-dns-audit-enhancements/spec.md`, which outlines enhancements for comprehensive security posture auditing and ensures consistent API stability.
