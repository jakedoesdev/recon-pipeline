# reconpipe (`rp`)

Composable recon pipeline for web and external assessments. Wraps BBOT and crt.sh for subdomain enumeration, then chains DNS resolution, security header auditing, scope tagging, anomaly detection, and structured reporting — all flowing through a single JSONL store with merge-on-FQDN semantics.

## Requirements

- Python 3.11+
- [BBOT 2.8.4+](https://github.com/blacklanternsecurity/bbot) (for `--bbot` enumeration)
- [WPScan](https://wpscan.com/) (for `rp wpscan` — pre-installed on Kali, or `apt install wpscan`)
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

# WPScan — used by `rp wpscan` for vulnerability database lookups (optional, scans work without it)
wpscan = "your_wpscan_token"

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

## Logging

### Verbosity

All commands accept root-level logging flags:

```bash
rp -v resolve -i store.jsonl          # DEBUG — show all DNS queries, HTTP requests, etc.
rp -q resolve -i store.jsonl          # WARNING only — suppress normal progress output
rp --log-file run.log resolve -i store.jsonl   # also write DEBUG-level output to file
```

`-v` and `-q` are mutually exclusive. `--log-file` always writes at DEBUG regardless of terminal verbosity.

### Provenance trail

Every writing command automatically generates a provenance log alongside the store:

```
store.jsonl                   # the main store
store.provenance.jsonl        # append-only evidence trail
```

The provenance file records a timestamped JSONL entry for every network request and decision point — DNS queries, HTTP checks, TLS connections, RDAP lookups, scope classifications, and analysis flags. Each entry includes the raw data that produced the corresponding store field, so a future `rp verify` command can trace any finding back to its source without re-running requests.

Example entries:

```json
{"ts":"2026-05-17T14:00:01+00:00","module":"resolve","action":"dns_resolve","fqdn":"app.example.com","detail":{"a":["93.184.216.34"],"aaaa":[],"cname_chain":[],"nxdomain":false}}
{"ts":"2026-05-17T14:00:03+00:00","module":"headers","action":"http_check","fqdn":"app.example.com","detail":{"scheme":"https","url":"https://app.example.com","status":200,"missing":["Content-Security-Policy"]}}
{"ts":"2026-05-17T14:00:05+00:00","module":"tls","action":"tls_connect","fqdn":"app.example.com","detail":{"subject":"*.example.com","issuer_org":"Let's Encrypt","not_after":"2026-06-30T00:00:00"}}
```

Query with jq:

```bash
# All failed HTTP checks
jq 'select(.action == "http_failed")' store.provenance.jsonl

# Evidence for a specific host
jq 'select(.fqdn == "app.example.com")' store.provenance.jsonl

# All takeover confirmations
jq 'select(.action == "takeover_http_confirmed")' store.provenance.jsonl
```

## Usage

### Individual commands (recommended)

Each phase can be run independently, reading from and writing to the same JSONL store. Start here — running each module individually lets you inspect output at every stage, tune flags, and understand what each phase contributes before chaining them together.

### Full pipeline

```bash
rp pipeline -i domains.txt -o store.jsonl --allow scope-allow.txt --deny scope-deny.txt
rp pipeline -i domains.txt -o store.jsonl --auto-scope   # auto-generate scope files
```

Runs all phases in sequence: enum → scope → resolve → reverse → headers → tls → rdap → wpscan → analyze. Use this once you're comfortable with the individual modules and know which options you want. For a first engagement, run each phase separately so you can review results between steps.

Scope files are validated before any work begins (see enum section above). At the end of the pipeline, any crt.sh failures or SAN-discovered hosts are saved to rescan files with suggested re-run commands.

#### Selective phases

Use `--phases` to run only specific phases. Scope and analyze are automatic — scope runs whenever unscoped FQDNs exist in the store, and analyze runs after any data-gathering phase completes.

```bash
rp pipeline -i domains.txt -o store.jsonl --phases enum,resolve,headers
rp pipeline -i domains.txt -o store.jsonl --phases e,res,h          # shorthand
rp pipeline -i domains.txt -o store.jsonl --phases wpscan            # just wpscan
rp pipeline -i domains.txt -o store.jsonl --phases rev,h,t           # reverse + headers + tls
```

Phase names and shorthand aliases:

| Short | Full |
|-------|------|
| `e` | `enum` |
| `res` | `resolve` |
| `rev` | `reverse` |
| `h` | `headers` |
| `t` | `tls` |
| `r` | `rdap` |
| `w` | `wpscan` |

Omit `--phases` to run all phases (default behavior).

#### 1. Subdomain enumeration

```bash
rp enum -i domains.txt -o store.jsonl
rp enum -i domains.txt -o store.jsonl --no-bbot          # crt.sh only
rp enum -i domains.txt -o store.jsonl --no-crtsh         # BBOT only
rp enum -i domains.txt -o store.jsonl --bbot-silent      # suppress BBOT terminal output
rp enum -i domains.txt -o store.jsonl --bbot-preset reconpipe-quiet
rp enum -i domains.txt -o store.jsonl --allow allow.txt --deny deny.txt  # use existing scope files
rp enum -i domains.txt -o store.jsonl --auto-scope       # auto-generate allow.txt without prompting
```

`domains.txt` is a newline-separated list of root domains:

```
example.com
target.org
```

**Scope enforcement:** If `--allow` is not provided, `enum` will offer to auto-generate an `allow.txt` with `*.rootdomain.tld` for each target domain and an empty `deny.txt` in the same directory as the targets file. Use `--auto-scope` to skip the interactive prompt. Scope is applied automatically after enumeration completes.

**crt.sh resilience:** If crt.sh fails for any target domain (after 4 retry attempts), the failed domain is saved to `crtsh-rescan.txt` next to the store file. A reminder with a ready-to-use re-run command is printed at the end:

```
⚠ 1 domain(s) failed crt.sh — saved to crtsh-rescan.txt
  Re-run with: rp enum -i crtsh-rescan.txt -o store.jsonl --no-bbot
```

#### 2. Add hosts manually

```bash
rp add -o store.jsonl -i sans-rescan.txt                              # from a file
rp add -o store.jsonl app.example.com api.example.com                 # inline
rp add -o store.jsonl -i extras.txt staging.example.com               # both
rp add -o store.jsonl -i crtsh-rescan.txt --source crtsh-retry        # custom source tag
```

Injects FQDNs directly into the store with `discovery_sources: ["manual"]` (or a custom `--source` tag). No network calls — just creates the store records so downstream modules (`rp scope`, `rp resolve`, etc.) can process them. Merges with existing records if the FQDN is already in the store.

Designed to work with the `sans-rescan.txt` and `crtsh-rescan.txt` files generated by `rp analyze` and `rp enum`:

```bash
# After initial pipeline, add SAN-discovered hosts and run remaining phases
rp add -o store.jsonl -i sans-rescan.txt --source sans-rescan
rp scope -i store.jsonl --allow allow.txt --deny deny.txt
rp resolve -i store.jsonl
rp headers -i store.jsonl
```

#### 3. Scope tagging

Scope is applied automatically after `rp enum` and `rp pipeline` (see above). You can also run it standalone to re-tag or apply redirect-deny rules:

```bash
rp scope -i store.jsonl --allow allow.txt --deny deny.txt
rp scope -i store.jsonl --allow allow.txt --deny deny.txt --redirect-deny redirect-deny.txt
```

Tags every host as `in`, `out`, or `unmatched`. Deny rules are evaluated first (deny wins). Hosts tagged `out` are skipped by all downstream modules (resolve, headers, tls, rdap, analyze) but remain in the store with any previously collected data intact.

Use `--redirect-deny` after running `rp headers` to exclude hosts whose redirect chain matches specified patterns. This is useful for filtering out large numbers of subdomains that all redirect to the same third-party login page or parked domain.

Scope file syntax:

```
# Exact match
api.example.com

# Wildcard (matches subdomains + the apex itself)
*.example.com

# Regex
re:.*\.dev\.example\.com
```

Redirect-deny file syntax (matched against full redirect URLs):

```
# Substring match against redirect chain URLs
login.microsoftonline.com
parked.example.com

# Regex
re:.*\.parked-domain\.com
```

#### 4. DNS resolution

```bash
rp resolve -i store.jsonl
rp resolve -i store.jsonl --resolvers 1.1.1.1,8.8.8.8   # custom resolvers
rp resolve -i store.jsonl --concurrency 100              # parallel lookups
rp resolve -i store.jsonl --no-wildcard-detect           # skip wildcard check
rp resolve -i store.jsonl --asn-db GeoLite2-ASN.mmdb --country-db GeoLite2-Country.mmdb
```

Resolves A, AAAA, and CNAME records. Walks CNAME chains (up to 10 hops). Detects wildcard DNS by querying 3 random labels per apex. Flags private IPs (RFC 1918, loopback, link-local).

#### 5. Reverse DNS

```bash
rp reverse -i store.jsonl
rp reverse -i store.jsonl --resolvers 1.1.1.1,8.8.8.8
rp reverse -i store.jsonl --concurrency 100
rp reverse -i store.jsonl --refresh                        # re-check all IPs
```

Performs PTR lookups on all unique public IPs discovered during resolution. PTR hostnames are stored on each `ResolvedIp` entry. Hosts sharing infrastructure often have PTR records pointing to hostnames not found by any passive source. Skips IPs that already have PTR data from prior runs; use `--refresh` to re-check all.

#### 6. Security headers

```bash
rp headers -i store.jsonl
rp headers -i store.jsonl --scheme both                  # check http and https
rp headers -i store.jsonl --force                        # check even unresolved hosts
rp headers -i store.jsonl --expected headers.txt         # custom expected headers file
rp headers -i store.jsonl --refresh                      # re-check all hosts
rp headers -i store.jsonl --concurrency 10               # limit concurrent requests
```

Checks for missing security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Permissions-Policy, Referrer-Policy). Records status code, server banner, and present headers. Runs concurrently (default 20 requests, capped at 3 per IP to avoid triggering WAFs). Skips hosts that already have header data from prior runs; use `--refresh` to re-check all.

#### 7. TLS certificate collection

```bash
rp tls -i store.jsonl
rp tls -i store.jsonl --port 8443                       # non-standard TLS port
rp tls -i store.jsonl --refresh                         # re-check all hosts
rp tls -i store.jsonl --concurrency 50                  # limit concurrent connections
```

Connects to each resolved host via TLS and extracts the live certificate: subject, issuer, validity dates, serial number, SANs, and self-signed status. SANs can reveal additional domains not found during enumeration. Requires the `cryptography` package. Runs concurrently (default 30 connections, capped at 5 per IP to avoid triggering rate limits). Skips hosts that already have TLS data from prior runs; use `--refresh` to re-check all.

#### 8. RDAP registration lookup

```bash
rp rdap -i store.jsonl
rp rdap -i store.jsonl --refresh                        # re-check all apex domains
```

Queries RDAP (the modern WHOIS replacement) once per apex domain. Collects registrar, registration/expiration dates, domain status codes, registered nameservers, and DNSSEC status. Data is shared across all subdomains of the same apex. Skips apex domains that already have RDAP data from prior runs; use `--refresh` to re-check all. To skip in the pipeline, omit `rdap` from `--phases`.

#### 9. WPScan

```bash
rp wpscan -i store.jsonl
rp wpscan -i store.jsonl --api-token YOUR_TOKEN          # override keys.toml
rp wpscan -i store.jsonl --refresh                       # re-scan all WordPress hosts
```

Scans WordPress hosts detected by `rp headers` (via technology fingerprinting — no path fuzzing or endpoint probing for identification). Requires `wpscan` on PATH (pre-installed on Kali, or `apt install wpscan`). Runs without an API token but warns that vulnerability data will not be available; add a `wpscan` key to `keys.toml` for full CVE lookups.

Captures: WordPress version and update status, active theme and version, all detected plugins and versions, known vulnerabilities/CVEs (with API token), and interesting findings (exposed endpoints, misconfigurations like XML-RPC, debug.log, directory listing). Raw WPScan JSON output is saved to `wpscan_out/` next to the store for manual review. Skips hosts that already have WPScan data from prior runs; use `--refresh` to re-scan all. To skip in the pipeline, omit `wpscan` from `--phases`.

#### 10. Analyze

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
- TLS SANs containing subdomains not in the store (potential undiscovered hosts)
- Private IPs leaked in HTTP headers, redirects, or response bodies (information disclosure)
- HTTP status code anomalies and version disclosure in headers
- Exposed lower environments (dev, staging, QA, UAT, test, sandbox, preprod, internal) detected via FQDN patterns and page titles
- WordPress vulnerabilities, outdated core/themes/plugins (from WPScan data)

Each flag is assigned a severity rating (critical, high, medium, low). The host's overall severity reflects its highest-severity flag for easy filtering.

**SAN-discovered hosts:** When TLS certificate SANs contain FQDNs not present in the store, they are saved to `sans-rescan.txt` next to the store file for potential re-scanning:

```
⚠ 12 SAN-discovered FQDN(s) not in store — saved to sans-rescan.txt
```

#### 11. Report

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

#### 12. Diff

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
| Models | `reconpipe/models.py` | Dataclasses: Host, DnsInfo, HeaderInfo, TlsInfo, ScopeInfo, AnalysisInfo, RdapInfo, WpscanInfo, ResolvedIp, LeakedIp |
| Store | `reconpipe/store.py` | JSONL read/write with merge-on-FQDN (unions discovery_sources, preserves phase data) |
| Log | `reconpipe/log.py` | Centralized logging setup, provenance trail (`<store>.provenance.jsonl`) |
| Config | `reconpipe/config.py` | Loads `config.toml` and `keys.toml`, resolves env var overrides |
| crt.sh | `reconpipe/enum/crtsh.py` | Certificate Transparency log queries with retry/backoff |
| BBOT | `reconpipe/enum/bbot.py` | Subprocess wrapper for BBOT, parses JSON output, passes secrets |
| Resolve | `reconpipe/resolve.py` | Async DNS (dnspython), CNAME walking, wildcard detection, MaxMind enrichment |
| Reverse | `reconpipe/reverse.py` | PTR (reverse DNS) lookups on discovered public IPs |
| Headers | `reconpipe/headers.py` | Security header checks, page title/technology detection, cookie analysis, private IP leak extraction |
| TLS | `reconpipe/tls.py` | Live TLS certificate collection (subject, issuer, SANs, expiry) |
| RDAP | `reconpipe/rdap.py` | RDAP registration lookups per apex (registrar, contacts, expiry, status, DNSSEC) |
| Scope | `reconpipe/scope.py` | Three-state classification with exact/wildcard/regex pattern matching |
| WPScan | `reconpipe/wpscan.py` | WPScan subprocess wrapper, JSON parsing, WordPress vulnerability detection |
| Analyze | `reconpipe/analyze.py` | Anomaly detection, takeover fingerprinting, TLS/CORS/cookie/WPScan checks, severity ratings |
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
    "redirect_chain": ["https://app.example.com/", "https://app.example.com/dashboard"],
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
    "contacts": [
      {"role": "registrar", "name": "Cloudflare, Inc.", "email": null, "phone": null, "org": null},
      {"role": "abuse", "name": "Cloudflare, Inc.", "email": "abuse@cloudflare.com", "phone": "+1.6503198930", "org": "Cloudflare, Inc."},
      {"role": "registrant", "name": "REDACTED FOR PRIVACY", "email": "proxy@example.com", "phone": null, "org": null}
    ],
    "registered_at": "2020-01-15T00:00:00Z",
    "expires_at": "2027-01-15T00:00:00Z",
    "statuses": ["clientTransferProhibited"],
    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "dnssec": true,
    "queried_at": "2026-05-17T12:00:00+00:00"
  },
  "wpscan": {
    "wp_version": "6.4.3",
    "wp_version_status": "latest",
    "theme": "flavor",
    "theme_version": "1.2.0",
    "theme_outdated": false,
    "plugins": [
      {"slug": "contact-form-7", "version": "5.9.3", "outdated": false, "vulnerabilities": []},
      {"slug": "elementor", "version": "3.18.0", "outdated": true, "vulnerabilities": [
        {"title": "Elementor < 3.19.0 - Stored XSS", "type": "XSS", "cve": "CVE-2024-XXXX", "fixed_in": "3.19.0"}
      ]}
    ],
    "vulnerabilities": [
      {"title": "Elementor < 3.19.0 - Stored XSS", "type": "XSS", "affects": "plugin:elementor", "cve": "CVE-2024-XXXX", "fixed_in": "3.19.0"}
    ],
    "interesting_findings": [
      {"url": "https://app.example.com/xmlrpc.php", "type": "xmlrpc", "description": "XML-RPC seems to be enabled", "references": {}}
    ],
    "scanned_at": "2026-05-17T14:00:10+00:00"
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
# Option A: provide scope files
echo "*.target.com" > allow.txt
echo "*.dev.target.com" > deny.txt
rp pipeline -i domains.txt -o target.jsonl --allow allow.txt --deny deny.txt --expected-country US

# Option B: auto-generate scope from targets (*.rootdomain.tld per target)
rp pipeline -i domains.txt -o target.jsonl --auto-scope --expected-country US

# Review flagged hosts
rp report -i target.jsonl --flagged-only --format csv -o flagged.csv

# Re-scan any failed crt.sh domains or SAN-discovered hosts
# (rescan files are written automatically if needed)
rp enum -i crtsh-rescan.txt -o target.jsonl --no-bbot     # if crt.sh failed
# sans-rescan.txt contains FQDNs found in TLS SANs but not in the store

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
