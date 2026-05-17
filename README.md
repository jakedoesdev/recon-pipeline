# reconpipe (`rp`)

Composable recon pipeline for web and external assessments. Wraps BBOT and crt.sh for subdomain enumeration, then chains DNS resolution, security header auditing, scope tagging, anomaly detection, and structured reporting — all flowing through a single JSONL store with merge-on-FQDN semantics.

## Requirements

- Python 3.11+
- [BBOT 2.8.4+](https://github.com/blacklanternsecurity/bbot) (for `--bbot` enumeration)
- Kali Linux (tested), any Linux should work

## Installation

```bash
# From the project directory
pipx install .

# Or in development mode
pip install -e .
```

This installs the `rp` command.

## Configuration

### Config directory

```
~/.config/reconpipe/
├── config.toml        # General settings (currently unused, reserved)
└── keys.toml          # API keys for enrichment services
```

Override the config directory with `RECONPIPE_CONFIG_DIR=/path/to/dir`.

### API Keys

Create `~/.config/reconpipe/keys.toml`:

```toml
[api_keys]
# ipinfo.io — used by `rp analyze --enrich-online` for ASN/country lookup
ipinfo = "your_ipinfo_token"

# Any BBOT module secrets (passed to BBOT via temp secrets.yml)
# Key names should match BBOT's expected secret names
virustotal = "your_vt_key"
shodan = "your_shodan_key"
securitytrails = "your_st_key"
```

Keys can also be set via environment variables using the pattern `RECONPIPE_<NAME>_KEY`:

```bash
export RECONPIPE_IPINFO_KEY="your_token"
export RECONPIPE_VIRUSTOTAL_KEY="your_key"
```

Environment variables take precedence over `keys.toml`.

### MaxMind GeoLite2 databases (optional)

For offline ASN and country enrichment during resolution:

```bash
rp resolve -i store.jsonl --asn-db /path/to/GeoLite2-ASN.mmdb --country-db /path/to/GeoLite2-Country.mmdb
```

Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free account required).

## Usage

### Full pipeline (recommended for first run)

```bash
rp pipeline -i domains.txt -o store.jsonl --allow scope-allow.txt --deny scope-deny.txt
```

This runs all phases in sequence: enum → resolve → headers → tls → rdap → scope → analyze.

### Individual commands

Each phase can be run independently, reading from and writing to the same JSONL store.

#### 1. Subdomain enumeration

```bash
rp enum -i domains.txt -o store.jsonl
rp enum -i domains.txt -o store.jsonl --no-bbot          # crt.sh only
rp enum -i domains.txt -o store.jsonl --no-crtsh         # BBOT only
rp enum -i domains.txt -o store.jsonl --bbot-silent      # suppress BBOT terminal output
rp enum -i domains.txt -o store.jsonl --bbot-preset reconpipe-quiet
```

`domains.txt` is a newline-separated list of root domains:

```
example.com
target.org
```

#### 2. DNS resolution

```bash
rp resolve -i store.jsonl
rp resolve -i store.jsonl --resolvers 1.1.1.1,8.8.8.8   # custom resolvers
rp resolve -i store.jsonl --concurrency 100              # parallel lookups
rp resolve -i store.jsonl --no-wildcard-detect           # skip wildcard check
rp resolve -i store.jsonl --asn-db GeoLite2-ASN.mmdb --country-db GeoLite2-Country.mmdb
```

Resolves A, AAAA, and CNAME records. Walks CNAME chains (up to 10 hops). Detects wildcard DNS by querying 3 random labels per apex. Flags private IPs (RFC 1918, loopback, link-local).

#### 3. Security headers

```bash
rp headers -i store.jsonl
rp headers -i store.jsonl --scheme both                  # check http and https
rp headers -i store.jsonl --source securityheaders       # use securityheaders.com
rp headers -i store.jsonl --source both                  # native + securityheaders.com
rp headers -i store.jsonl --force                        # check even unresolved hosts
rp headers -i store.jsonl --expected headers.txt         # custom expected headers file
```

Checks for missing security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Permissions-Policy, Referrer-Policy). Records status code, server banner, and present headers.

#### 4. TLS certificate collection

```bash
rp tls -i store.jsonl
rp tls -i store.jsonl --port 8443                       # non-standard TLS port
```

Connects to each resolved host via TLS and extracts the live certificate: subject, issuer, validity dates, serial number, SANs, and self-signed status. SANs can reveal additional domains not found during enumeration. Requires the `cryptography` package.

#### 5. RDAP registration lookup

```bash
rp rdap -i store.jsonl
```

Queries RDAP (the modern WHOIS replacement) once per apex domain. Collects registrar, registration/expiration dates, domain status codes, registered nameservers, and DNSSEC status. Data is shared across all subdomains of the same apex. Skip with `rp pipeline --no-rdap`.

#### 6. Scope tagging

```bash
rp scope -i store.jsonl --allow allow.txt --deny deny.txt
```

Tags every host as `in`, `out`, or `unmatched`. Deny rules are evaluated first (deny wins).

Scope file syntax:

```
# Exact match
api.example.com

# Wildcard (matches subdomains + the apex itself)
*.example.com

# Regex
re:.*\.dev\.example\.com
```

#### 7. Analyze

```bash
rp analyze -i store.jsonl
rp analyze -i store.jsonl --expected-country US
rp analyze -i store.jsonl --enrich-online               # ipinfo.io fallback for ASN/country
```

Detects:
- Stale CNAMEs (chain exists but resolves to nothing, or target domain is unregistered)
- Subdomain takeover candidates (17 services: S3, Azure, GitHub Pages, Heroku, Shopify, Fastly, Netlify, CloudFront, etc.)
- Geographic mismatches (IPs in unexpected countries)
- Private IPs on public DNS records
- Multiple apex owners (2+ non-CDN ASNs under one domain, CDN-aware)
- SPF misconfigurations (+all or ?all)
- NS delegation takeover risks (nameserver hostname is NXDOMAIN)
- Dangling MX records (mail server hostname is NXDOMAIN)
- Domain expiration warnings (RDAP: expiring within 60 days, expired, risky statuses)
- Missing DNSSEC delegation signing
- Expired or expiring TLS certificates, self-signed certs
- CORS misconfigurations (wildcard origin with credentials)
- Cookie security (missing Secure, HttpOnly flags)
- HTTP status code anomalies and version disclosure in headers

Each flag is assigned a severity rating (critical, high, medium, low). The host's overall severity reflects its highest-severity flag for easy filtering.

#### 8. Report

```bash
rp report -i store.jsonl --view combined                 # full JSONL (default)
rp report -i store.jsonl --view combined --format csv    # CSV export
rp report -i store.jsonl --view combined --format json-array  # JSON array
rp report -i store.jsonl --view subs                     # plain subdomain list
rp report -i store.jsonl --view ips                      # unique IPs
rp report -i store.jsonl --view subs-ips                 # fqdn,ip,record_type CSV
rp report -i store.jsonl --view headers                  # header audit CSV
rp report -i store.jsonl --scope all                     # all scope buckets
rp report -i store.jsonl --scope in,unmatched            # multiple buckets
rp report -i store.jsonl --flagged-only                  # only hosts with analysis flags
rp report -i store.jsonl --view subs -o subs.txt         # write to file
```

#### 9. Diff

```bash
rp diff --old scan1.jsonl --new scan2.jsonl
rp diff --old scan1.jsonl --new scan2.jsonl --format json
rp diff --old scan1.jsonl --new scan2.jsonl --format csv
rp diff --old scan1.jsonl --new scan2.jsonl --scope all
rp diff --old scan1.jsonl --new scan2.jsonl -o changes.txt
```

Compares two snapshots and reports:
- **Added** — new FQDNs in the current snapshot
- **Removed** — FQDNs that disappeared
- **Changed** — hosts where IPs, CNAME chains, headers, scope, flags, or discovery sources shifted

## Modules

| Module | File | Purpose |
|--------|------|---------|
| CLI | `reconpipe/cli.py` | Click command group, argument parsing, pipeline orchestration |
| Models | `reconpipe/models.py` | Dataclasses: Host, DnsInfo, HeaderInfo, TlsInfo, ScopeInfo, AnalysisInfo, RdapInfo, ResolvedIp |
| Store | `reconpipe/store.py` | JSONL read/write with merge-on-FQDN (unions discovery_sources, preserves phase data) |
| Config | `reconpipe/config.py` | Loads `config.toml` and `keys.toml`, resolves env var overrides |
| crt.sh | `reconpipe/enum/crtsh.py` | Certificate Transparency log queries with retry/backoff |
| BBOT | `reconpipe/enum/bbot.py` | Subprocess wrapper for BBOT, parses JSON output, passes secrets |
| Resolve | `reconpipe/resolve.py` | Async DNS (dnspython), CNAME walking, wildcard detection, MaxMind enrichment |
| Headers | `reconpipe/headers.py` | Security header checks, page title/technology detection, cookie analysis |
| TLS | `reconpipe/tls.py` | Live TLS certificate collection (subject, issuer, SANs, expiry) |
| RDAP | `reconpipe/rdap.py` | RDAP registration lookups per apex (registrar, expiry, status, DNSSEC) |
| Scope | `reconpipe/scope.py` | Three-state classification with exact/wildcard/regex pattern matching |
| Analyze | `reconpipe/analyze.py` | Anomaly detection, takeover fingerprinting, TLS/CORS/cookie checks, severity ratings |
| Fingerprints | `reconpipe/fingerprints.py` | 17 subdomain takeover fingerprints (S3, Azure, GitHub Pages, etc.) |
| Report | `reconpipe/report.py` | Output views: subs, ips, subs-ips, headers, combined (JSONL/JSON/CSV) |
| Diff | `reconpipe/diff.py` | Structured snapshot comparison (added/removed/changed) |
| Presets | `reconpipe/presets/` | BBOT preset YAML files |

## Data model

All data lives in a single JSONL file (one JSON object per line, keyed by FQDN). Each phase enriches the record additively — fields left `null` until their phase runs:

```json
{
  "fqdn": "app.example.com",
  "apex": "example.com",
  "discovery_sources": ["crtsh", "bbot:certspotter"],
  "dns": {
    "a": ["93.184.216.34"],
    "aaaa": [],
    "cname_chain": ["app.example.com.cdn.cloudflare.net"],
    "resolved_ips": [{"ip": "93.184.216.34", "record_type": "A", "is_private": false, "asn": 13335, "country": "US"}],
    "nxdomain": false
  },
  "headers": {
    "status_code": 200,
    "present": {"strict-transport-security": "max-age=31536000", "x-frame-options": "DENY", "server": "cloudflare"},
    "missing": ["Content-Security-Policy", "Permissions-Policy"],
    "page_title": "App Dashboard",
    "meta_generator": null,
    "technologies": [],
    "cookies": [{"name": "session", "secure": true, "httponly": true, "samesite": "Strict"}],
    "source": "native"
  },
  "tls": {
    "subject": "*.example.com",
    "issuer": "R11",
    "issuer_org": "Let's Encrypt",
    "not_before": "2026-04-01T00:00:00",
    "not_after": "2026-06-30T00:00:00",
    "serial": "04a3b5c7d9e1f2",
    "sans": ["*.example.com", "example.com"],
    "self_signed": false
  },
  "scope": {
    "status": "in",
    "matched_rule": "allow:*.example.com",
    "warning": null
  },
  "analysis": {
    "flags": [],
    "severity": null,
    "takeover_candidate": false
  },
  "rdap": {
    "registrar": "Cloudflare, Inc.",
    "registered_at": "2020-01-15T00:00:00Z",
    "expires_at": "2027-01-15T00:00:00Z",
    "statuses": ["clientTransferProhibited"],
    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "dnssec": true,
    "queried_at": "2026-05-17T12:00:00+00:00"
  }
}
```

## BBOT presets

The default preset (`reconpipe-quiet`) runs passive-only subdomain enumeration:

```yaml
description: "Passive sources only, suitable for early-engagement recon"
flags:
  - subdomain-enum
require_flags:
  - passive
output_modules:
  - subdomains
  - json
```

Custom presets can be used with `--bbot-preset <name>` (BBOT looks in `~/.bbot/presets/` and its built-in preset directory).

## Examples

### Quick passive recon

```bash
echo "example.com" > targets.txt
rp enum -i targets.txt -o example.jsonl --no-bbot
rp resolve -i example.jsonl
rp report -i example.jsonl --view subs
```

### Full assessment workflow

```bash
# Create scope files
echo "*.target.com" > allow.txt
echo "*.dev.target.com" > deny.txt

# Run everything
rp pipeline -i domains.txt -o target.jsonl --allow allow.txt --deny deny.txt --expected-country US

# Review flagged hosts
rp report -i target.jsonl --flagged-only --format csv -o flagged.csv

# Next week — diff against baseline
rp pipeline -i domains.txt -o target-week2.jsonl --allow allow.txt --deny deny.txt
rp diff --old target.jsonl --new target-week2.jsonl --format text
```

### Export for other tools

```bash
# Feed IPs to nmap
rp report -i store.jsonl --view ips -o live-ips.txt
nmap -iL live-ips.txt -sV -oA scan

# Feed subdomains to other tools
rp report -i store.jsonl --view subs --scope in -o inscope-subs.txt
```
