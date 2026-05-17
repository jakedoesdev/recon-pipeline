# reconpipe Help Guide

## Part 1: JSONL Record Fields

Each line in the `.jsonl` store is a **Host** record with the following top-level fields:

### Host (top-level)

| Field | Type | Description |
|---|---|---|
| `fqdn` | string | Fully qualified domain name (e.g. `shop.tesla.com`). The primary key for each record. |
| `apex` | string | The registrable domain (e.g. `tesla.com`). Derived from the FQDN using `tldextract`. |
| `discovery_sources` | list | Where this subdomain was found (e.g. `["crtsh", "bbot:certspotter"]`). Multiple sources are merged if the same FQDN is discovered by different tools. |
| `first_seen` | string | ISO 8601 timestamp of when the host was first added to the store. |
| `last_updated` | string | ISO 8601 timestamp of the most recent update (any field change). |
| `dns` | object or null | DNS resolution data. Null if `rp resolve` hasn't been run yet. |
| `headers` | object or null | HTTP security header data. Null if `rp headers` hasn't been run yet. |
| `scope` | object or null | Scope classification. Null if `rp scope` hasn't been run yet. |
| `analysis` | object or null | Anomaly detection results. Null if `rp analyze` hasn't been run yet. |

### dns (DnsInfo)

Populated by `rp resolve`. Contains the full DNS resolution picture for the host.

| Field | Type | Description |
|---|---|---|
| `a` | list | IPv4 addresses from A record lookups on the FQDN itself. |
| `aaaa` | list | IPv6 addresses from AAAA record lookups. |
| `cname_chain` | list | Ordered sequence of CNAME hops the resolver followed before reaching a terminal A/AAAA record. For example, `["shop.tesla.com.cdn.cloudflare.net", "edge.cloudflare.net"]` means the FQDN is an alias that chains through two intermediate hostnames before resolving to IPs. An empty list means the FQDN resolves directly (no aliases). This field reveals the infrastructure stack (CDNs, load balancers, third-party services) and is critical for subdomain takeover analysis — a dangling CNAME with no IP resolution is a takeover candidate. |
| `resolved_ips` | list | Deduplicated list of all IPs the FQDN ultimately resolves to, including IPs obtained by following the CNAME chain to its terminal target. Each entry is a `ResolvedIp` object (see below). |
| `nxdomain` | bool | `true` if the domain does not exist (NXDOMAIN response). When true, all other DNS fields will be empty. |
| `resolver_used` | string | Comma-separated list of DNS resolvers used (e.g. `"1.1.1.1,8.8.8.8,9.9.9.9"`). |
| `resolved_at` | string | ISO 8601 timestamp of when the resolution was performed. |

**Note:** The resolver currently queries A, AAAA, and CNAME records. TXT, MX, NS, and SOA records are not collected — queries for those record types will return no results.

### resolved_ips[] (ResolvedIp)

Each entry in `dns.resolved_ips`:

| Field | Type | Description |
|---|---|---|
| `ip` | string | The IP address. |
| `record_type` | string | How this IP was obtained: `"A"` (direct A lookup), `"AAAA"` (direct AAAA lookup), or `"CNAME->A"` (resolved by following the CNAME chain to its final target). |
| `is_private` | bool | `true` if the IP is in RFC 1918 private space, loopback, link-local, or reserved ranges. A public FQDN resolving to a private IP is flagged during analysis. |
| `asn` | int or null | Autonomous System Number. Populated if a MaxMind ASN database was provided to `rp resolve`, or by `rp analyze --enrich-online`. |
| `asn_org` | string or null | Organization name for the ASN (e.g. `"Cloudflare, Inc."`). |
| `country` | string or null | ISO country code (e.g. `"US"`). Populated via MaxMind GeoIP or online enrichment. |

### headers (HeaderInfo)

Populated by `rp headers`. Contains the results of HTTP security header probing.

| Field | Type | Description |
|---|---|---|
| `url_checked` | string | The actual URL that was probed. This may differ from the FQDN if the request followed redirects or CNAME resolution landed on a different site. **Important:** If this doesn't match the FQDN, the header data (status code, present/missing headers) describes the destination site, not the original subdomain. Always compare this field against the FQDN to catch mismatches. |
| `status_code` | int | HTTP status code returned (e.g. `200`, `301`, `403`). |
| `present` | dict | Security headers that were found in the response, as `{header_name: header_value}` pairs. |
| `missing` | list | Security headers that were expected but not found (e.g. `["Strict-Transport-Security", "X-Content-Type-Options"]`). Checked against a default or user-provided expected-headers list. |
| `source` | string | How the check was performed: `"native"` (direct HTTP request) or `"securityheaders"` (via securityheaders.com API). |
| `grade` | string or null | Security grade if available (from securityheaders.com). Null for native checks. |
| `checked_at` | string | ISO 8601 timestamp of the header check. |

### scope (ScopeInfo)

Populated by `rp scope`. Classifies each host against your allow/deny lists.

| Field | Type | Description |
|---|---|---|
| `status` | string | One of three values: `"in"` (matched an allow rule — authorized target), `"out"` (matched a deny rule — explicitly excluded), or `"unmatched"` (no rule covers this host — needs review). Deny rules take priority over allow rules. |
| `matched_rule` | string or null | The specific rule that matched (e.g. `"allow:*.tesla.com"` or `"deny:*.cloudfront.net"`). Null for unmatched hosts. |
| `warning` | string or null | Advisory message. Set for unmatched hosts to prompt review. |

### analysis (AnalysisInfo)

Populated by `rp analyze`. Contains automated anomaly detection results.

| Field | Type | Description |
|---|---|---|
| `flags` | list | List of anomaly tags detected. Possible values: `"wildcard_dns"` (host resolves to known wildcard IPs for its apex), `"stale_cname"` (CNAME chain exists but resolves to nothing — takeover candidate), `"takeover:<service>"` (CNAME matches a known vulnerable service fingerprint, e.g. `"takeover:github"`), `"geo_mismatch:<CC>"` (IP in an unexpected country), `"private_ip_external"` (public DNS resolves to private/reserved IP), `"ipv4_only"` / `"ipv6_only"` (informational), `"multiple_apex_owners"` (apex has IPs across 3+ distinct ASNs). |
| `takeover_candidate` | bool | `true` if any `takeover:*` flag was set. Quick filter for high-priority findings. |
| `notes` | string or null | Free-text field for additional context. |

---

## Part 2: Useful Commands

All examples assume your store is at `/tmp/store.jsonl`. Add `--scope all` whenever you haven't run `rp scope` yet, or want results regardless of scope status.

### Built-in report views

```bash
# All unique IPs (public only)
rp report --view ips --scope all -i /tmp/store.jsonl

# All unique IPs including private/reserved
rp report --view ips --scope all -i /tmp/store.jsonl --flagged-only  # (or pipe through jq)

# All subdomains
rp report --view subs --scope all -i /tmp/store.jsonl

# Subdomain-to-IP mapping (CSV: fqdn,ip,record_type)
rp report --view subs-ips --scope all -i /tmp/store.jsonl

# Security headers summary (CSV)
rp report --view headers --scope all -i /tmp/store.jsonl

# Full records as JSON (one per line)
rp report --view combined --scope all -i /tmp/store.jsonl

# Only hosts that have analysis flags
rp report --view combined --scope all --flagged-only -i /tmp/store.jsonl

# Write any view to a file
rp report --view ips --scope all -i /tmp/store.jsonl -o live-ips.txt
```

### Querying specific hosts with jq

The `combined` view outputs full Host objects as JSONL, which you can filter with `jq`.

```bash
# Shorthand alias for the base command
alias rpq='rp report --view combined --scope all -i /tmp/store.jsonl'
```

**Look up a specific subdomain (exact match):**
```bash
rpq | jq 'select(.fqdn == "shop.tesla.com")'
```

**Look up a specific IP (any host resolving to it):**
```bash
rpq | jq 'select(.dns.resolved_ips[]?.ip == "204.74.99.100")'
```

**Look up multiple subdomains:**
```bash
rpq | jq 'select(.fqdn == "shop.tesla.com" or .fqdn == "api.tesla.com")'
```

**Look up multiple IPs:**
```bash
rpq | jq 'select([.dns.resolved_ips[]?.ip] | any(. == "151.101.2.92" or . == "204.74.99.100"))'
```

**Partial/pattern match on FQDN:**
```bash
# All subdomains containing "shop"
rpq | jq 'select(.fqdn | test("shop"))'

# All subdomains starting with "api"
rpq | jq 'select(.fqdn | test("^api\\."))'

# All subdomains under a specific subdomain tree
rpq | jq 'select(.fqdn | endswith(".dev.tesla.com"))'
```

**Search by IP subnet/prefix:**
```bash
# All hosts on 151.101.x.x
rpq | jq 'select(.dns.resolved_ips[]?.ip | test("^151\\.101\\."))'
```

### Header analysis queries

**Hosts where url_checked doesn't match the FQDN (redirect/CNAME mismatch):**
```bash
# The header probe landed on a different site than expected
rpq | jq 'select(.headers != null and (.headers.url_checked | test(.fqdn; "x") | not))' 

# Simpler version — url_checked doesn't contain the fqdn
rpq | jq 'select(.headers != null and (.headers.url_checked | contains(.fqdn) | not))'
```

**Hosts where the FQDN appears in url_checked (no mismatch):**
```bash
rpq | jq 'select(.headers != null and (.headers.url_checked | contains(.fqdn)))'
```

**Hosts missing a specific security header:**
```bash
# Missing HSTS
rpq | jq 'select(.headers.missing[]? == "Strict-Transport-Security")'

# Missing multiple specific headers
rpq | jq 'select(.headers != null and ([.headers.missing[]?] | any(. == "Strict-Transport-Security" or . == "X-Content-Type-Options")))'
```

**Hosts with a specific status code:**
```bash
rpq | jq 'select(.headers.status_code == 403)'
```

**Hosts behind a specific server (e.g. Cloudflare):**
```bash
rpq | jq 'select(.headers.present.server? | test("cloudflare"; "i"))'
```

### DNS-specific queries

**All hosts with a CNAME chain (not resolving directly):**
```bash
rpq | jq 'select(.dns.cname_chain | length > 0)'
```

**Hosts whose CNAME chain includes a specific provider:**
```bash
rpq | jq 'select([.dns.cname_chain[]?] | any(test("cloudfront")))'
rpq | jq 'select([.dns.cname_chain[]?] | any(test("fastly")))'
rpq | jq 'select([.dns.cname_chain[]?] | any(test("herokuapp")))'
```

**NXDOMAIN hosts (domain doesn't exist):**
```bash
rpq | jq 'select(.dns.nxdomain == true)'
```

**Hosts with no DNS data at all (not yet resolved):**
```bash
rpq | jq 'select(.dns == null)'
```

**Hosts that resolved but returned no IPs (empty resolution):**
```bash
rpq | jq 'select(.dns != null and .dns.nxdomain == false and (.dns.resolved_ips | length == 0))'
```

**Hosts resolving to private IPs:**
```bash
rpq | jq 'select([.dns.resolved_ips[]?] | any(.is_private == true))'
```

**IPv6-only hosts:**
```bash
rpq | jq 'select(.dns != null and (.dns.aaaa | length > 0) and (.dns.a | length == 0))'
```

### Analysis and flag queries

**Subdomain takeover candidates:**
```bash
rpq | jq 'select(.analysis.takeover_candidate == true)'
```

**Stale CNAMEs (dangling, no resolution):**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("stale_cname")))'
```

**Wildcard DNS flagged hosts:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "wildcard_dns"))'
```

**Any host with at least one flag:**
```bash
rpq | jq 'select(.analysis.flags | length > 0)'
```

**Geo-mismatch hosts:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("geo_mismatch")))'
```

### Scope queries

**Unscoped or unmatched hosts:**
```bash
rpq | jq 'select(.scope == null or .scope.status == "unmatched")'
```

**Out-of-scope hosts only:**
```bash
rp report --view combined --scope out -i /tmp/store.jsonl
```

### Discovery source queries

**Hosts found by a specific source:**
```bash
rpq | jq 'select(.discovery_sources[]? | test("crtsh"))'
rpq | jq 'select(.discovery_sources[]? | test("bbot"))'
```

**Hosts found by multiple sources (cross-validated):**
```bash
rpq | jq 'select(.discovery_sources | length > 1)'
```

### Aggregation and counting

```bash
# Count hosts per apex
rpq | jq -r '.apex' | sort | uniq -c | sort -rn

# Count hosts per discovery source
rpq | jq -r '.discovery_sources[]' | sort | uniq -c | sort -rn

# Count unique IPs per ASN org
rpq | jq -r '[.dns.resolved_ips[]? | select(.asn_org != null) | .asn_org] | unique[]' | sort | uniq -c | sort -rn

# List all unique CNAME targets across the store
rpq | jq -r '.dns.cname_chain[]?' | sort -u

# Count hosts by scope status
rpq | jq -r '.scope.status // "null"' | sort | uniq -c | sort -rn

# Count hosts by HTTP status code
rpq | jq -r 'select(.headers != null) | .headers.status_code' | sort | uniq -c | sort -rn
```

### Combining filters

Filters chain naturally with `jq`. Combine any of the above with `and`/`or`:

```bash
# In-scope hosts with stale CNAMEs pointing to AWS
rpq | jq 'select(
  .scope.status == "in" and
  ([.analysis.flags[]?] | any(. == "stale_cname")) and
  ([.dns.cname_chain[]?] | any(test("amazonaws")))
)'

# Hosts discovered by crtsh that have header mismatches
rpq | jq 'select(
  (.discovery_sources[]? | test("crtsh")) and
  .headers != null and
  (.headers.url_checked | contains(.fqdn) | not)
)'
```

### Extracting specific fields

```bash
# Just FQDNs and their CNAME chains
rpq | jq '{fqdn, cname_chain: .dns.cname_chain}'

# FQDN + IP + ASN org table
rpq | jq -r '[.fqdn, (.dns.resolved_ips[]? | "\(.ip) \(.asn_org // "unknown")")] | join(",")'

# Compact summary: fqdn, scope, flags
rpq | jq '{fqdn, scope: .scope.status, flags: .analysis.flags}'
```
