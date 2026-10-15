# DomainMapper

**Simple domain-to-infrastructure OSINT tool for authorized reconnaissance.**

Maps: `Domain → DNS → Subdomains → IPs → ASN/Org → Cloud providers → Findings`

> **Authorized use only.** Only scan domains you own or have explicit permission to assess.

## One-command install & run

```bash
pip install dnspython
python -m domainmapper example.test
```

Or install the package:

```bash
pip install -e .
domainmapper example.test
```

## Usage

```bash
# Basic passive scan (Certificate Transparency + DNS)
domainmapper example.test

# With wordlist
domainmapper example.test -w examples/wordlist.txt

# JSON to stdout + custom output dir
domainmapper example.test -j -o ./out

# Quiet / verbose
domainmapper example.test -q
domainmapper example.test -v
```

**Options:** `--workers`, `--rate`, `--timeout`, `-w`, `-o`, `-j`, `-q`, `-v`

## What it collects

| Layer | Data |
|-------|------|
| DNS | A, AAAA, MX, NS, TXT, SOA, CAA, CNAME |
| Subdomains | Certificate Transparency (crt.sh) + optional wordlist |
| IPs | Reverse DNS, ASN, org, country, ISP |
| Cloud | Cloudflare, AWS, Azure, GCP, DigitalOcean, Akamai, Fastly, … |
| Findings | Missing SPF/CAA, possible dangling CNAMEs |

Passive only. No exploitation, no brute-force, no credential attacks.

## Scope

Every hostname is checked against the target domain (and `*.domain`). Out-of-scope names are skipped.

## Report

JSON written to `reports/<domain>_<timestamp>.json`.

## License

MIT

## Responsible use

DomainMapper is intended only for authorized security assessments, bug bounty programs, security research, and infrastructure you own or are explicitly authorized to assess.
