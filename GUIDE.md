# reconpipe Help Guide

## Part 1: JSONL Record Fields

Each line in the `.jsonl` store is a **Host** record with the following top-level fields:

### Host (top-level)

| Field | Type | Description |
|---|---|---|
| `fqdn` | string | Fully qualified domain name (e.g. `shop.example.com`). The primary key for each record. |
| `apex` | string | The registrable domain (e.g. `example.com`). Derived from the FQDN using `tldextract`. |
| `discovery_sources` | list | Where this subdomain was found (e.g. `["crtsh", "bbot:certspotter"]`). Multiple sources are merged if the same FQDN is discovered by different tools. |
| `first_seen` | string | ISO 8601 timestamp of when the host was first added to the store. |
| `last_updated` | string | ISO 8601 timestamp of the most recent update (any field change). |
| `dns` | object or null | DNS resolution data. Null if `rp resolve` hasn't been run yet. |
| `headers` | object or null | HTTP security header data. Null if `rp headers` hasn't been run yet. |
| `scope` | object or null | Scope classification. Null if `rp scope` hasn't been run yet. |
| `analysis` | object or null | Anomaly detection results. Null if `rp analyze` hasn't been run yet. |
| `tls` | object or null | Live TLS certificate data. Null if `rp tls` hasn't been run yet. |
| `rdap` | object or null | RDAP registration data for the host's apex domain. Null if `rp rdap` hasn't been run yet. Shared across all hosts under the same apex. |

### dns (DnsInfo)

Populated by `rp resolve`. Contains the full DNS resolution picture for the host.

| Field | Type | Description |
|---|---|---|
| `a` | list | IPv4 addresses from A record lookups on the FQDN itself. |
| `aaaa` | list | IPv6 addresses from AAAA record lookups. |
| `txt` | list | TXT record values. Can contain SPF policies, DKIM keys, domain verification tokens (e.g. Google, Microsoft, AWS), and other metadata. Useful for identifying services tied to a domain and spotting information disclosure. |
| `mx` | list | MX (mail exchange) record values, in `priority hostname` format (e.g. `"10 mail.example.com"`). Reveals mail infrastructure — self-hosted mail servers, third-party providers (Google Workspace, O365), or the absence of mail handling. |
| `ns` | list | NS (nameserver) record values. Shows which DNS servers are authoritative for the FQDN. Useful for identifying the DNS provider, spotting delegation to third parties, and checking for zone transfer opportunities. |
| `cname_chain` | list | Ordered sequence of CNAME hops the resolver followed before reaching a terminal A/AAAA record. For example, `["shop.example.com.cdn.cloudflare.net", "edge.cloudflare.net"]` means the FQDN is an alias that chains through two intermediate hostnames before resolving to IPs. An empty list means the FQDN resolves directly (no aliases). This field reveals the infrastructure stack (CDNs, load balancers, third-party services) and is critical for subdomain takeover analysis — a dangling CNAME with no IP resolution is a takeover candidate. |
| `resolved_ips` | list | Deduplicated list of all IPs the FQDN ultimately resolves to, including IPs obtained by following the CNAME chain to its terminal target. Each entry is a `ResolvedIp` object (see below). |
| `nxdomain` | bool | `true` if the domain does not exist (NXDOMAIN response). When true, all other DNS fields will be empty. |
| `resolver_used` | string | Comma-separated list of DNS resolvers used (e.g. `"1.1.1.1,8.8.8.8,9.9.9.9"`). |
| `resolved_at` | string | ISO 8601 timestamp of when the resolution was performed. |

**Note:** The resolver queries A, AAAA, TXT, MX, NS, and CNAME records. SOA records are not collected.

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
| `ptr` | string or null | Reverse DNS (PTR) hostname for this IP. Populated by `rp reverse`. Null if no PTR record exists or `rp reverse` hasn't been run. |

### headers (HeaderInfo)

Populated by `rp headers`. Contains the results of HTTP security header probing.

| Field | Type | Description |
|---|---|---|
| `url_checked` | string | The actual URL that was probed. This may differ from the FQDN if the request followed redirects or CNAME resolution landed on a different site. **Important:** If this doesn't match the FQDN, the header data (status code, present/missing headers) describes the destination site, not the original subdomain. Always compare this field against the FQDN to catch mismatches. |
| `status_code` | int | HTTP status code returned (e.g. `200`, `301`, `403`). |
| `redirect_chain` | list | Full redirect chain as URLs, from the original request through each redirect to the final destination. Empty list if no redirects occurred. Useful for identifying hosts that all redirect to the same third-party service. Can be used with `rp scope --redirect-deny` to filter them out. |
| `present` | dict | Security headers and informational headers found in the response, as `{header_name: header_value}` pairs. Includes expected security headers, `server`, `x-powered-by`, CORS headers (`access-control-allow-origin`, `access-control-allow-credentials`), and all `X-` prefixed headers from the response. |
| `missing` | list | Security headers that were expected but not found (e.g. `["Strict-Transport-Security", "X-Content-Type-Options"]`). Checked against a default or user-provided expected-headers list. |
| `page_title` | string or null | The content of the `<title>` tag from the HTML response body. Quick identification of what's running (e.g. `"Welcome to nginx!"`, `"Confluence"`, `"GitLab"`). Null if no title tag found or the page returned no body. |
| `meta_generator` | string or null | The `<meta name="generator">` content, which CMS and frameworks typically set (e.g. `"WordPress 6.4"`, `"Drupal 10"`, `"Hugo 0.121.0"`). Null if not present. |
| `technologies` | list | Technologies detected in the response body via pattern matching. Detects: WordPress, Drupal, Joomla, Next.js, Nuxt.js, Angular, React, Shopify, Squarespace, Wix, Confluence, Jira, GitLab, Grafana, Jenkins, Kibana, phpMyAdmin, nginx, Apache Tomcat, IIS, Laravel, Gatsby, HubSpot. |
| `cookies` | list | Cookies set by the response, with security attribute analysis. Each entry is `{"name": "session_id", "secure": true, "httponly": true, "samesite": "Strict"}`. Missing attributes are flagged by analyze. |
| `body_snippet` | string or null | First 5,000 characters of the response body. Used by analyze for takeover confirmation without re-fetching. Null if no body was returned. |
| `source` | string | Always `"native"` (direct HTTP request). |
| `grade` | string or null | Reserved for future use. |
| `checked_at` | string | ISO 8601 timestamp of the header check. |

### tls (TlsInfo)

Populated by `rp tls`. Contains the live TLS certificate served by the host.

| Field | Type | Description |
|---|---|---|
| `subject` | string or null | Certificate subject Common Name (CN). Usually the domain the cert was issued for. |
| `issuer` | string or null | Certificate issuer Common Name (e.g. `"R11"` for Let's Encrypt, `"DigiCert Global G2"`). |
| `issuer_org` | string or null | Certificate issuer Organization (e.g. `"Let's Encrypt"`, `"DigiCert Inc"`). Useful for identifying who issued the cert. |
| `not_before` | string or null | ISO 8601 timestamp of when the certificate became valid. |
| `not_after` | string or null | ISO 8601 timestamp of when the certificate expires. Expiring/expired certs are flagged by analyze. |
| `serial` | string or null | Certificate serial number in hex. Useful for tracking specific certificates. |
| `sans` | list | Subject Alternative Names — all domain names the certificate covers. Can reveal additional subdomains or related domains not discovered during enumeration. |
| `self_signed` | bool | `true` if the certificate issuer matches the subject (self-signed). Flagged by analyze. |
| `queried_at` | string | ISO 8601 timestamp of the TLS handshake. |

### scope (ScopeInfo)

Populated by `rp scope`. Classifies each host against your allow/deny lists.

| Field | Type | Description |
|---|---|---|
| `status` | string | One of three values: `"in"` (matched an allow rule — authorized target), `"out"` (matched a deny rule — explicitly excluded, skipped by all downstream modules), or `"unmatched"` (no rule covers this host — needs review). Deny rules take priority over allow rules. |
| `matched_rule` | string or null | The specific rule that matched (e.g. `"allow:*.example.com"` or `"deny:*.cloudfront.net"`). Null for unmatched hosts. |
| `warning` | string or null | Advisory message. Set for unmatched hosts to prompt review. |

### analysis (AnalysisInfo)

Populated by `rp analyze`. Contains automated anomaly detection results.

| Field | Type | Description |
|---|---|---|
| `severity` | string or null | Highest severity across all flags for this host: `"critical"`, `"high"`, `"medium"`, or `"low"`. Null if no flags are set. Severity is computed automatically from the flag types (see severity table below). |
| `flags` | list | List of anomaly tags detected. Possible values: `"wildcard_dns"` (host resolves to known wildcard IPs for its apex), `"stale_cname"` (CNAME chain exists but resolves to nothing — takeover candidate), `"takeover:<service>"` (CNAME matches a known vulnerable service fingerprint, e.g. `"takeover:github"`), `"geo_mismatch:<CC>"` (IP in an unexpected country), `"private_ip_external"` (public DNS resolves to private/reserved IP), `"multiple_apex_owners"` (apex has IPs across 2+ distinct non-CDN ASNs — CDN providers like Cloudflare, Fastly, and Akamai are excluded from the count), `"unexpected_asn:<asn>"` (host's non-CDN ASN differs from the majority ASN for its apex — potential outlier worth investigating), `"spf_permissive"` (SPF record uses `+all` or `?all` — allows any server to spoof mail), `"ns_takeover_risk:<ns_host>"` (NS record points to a provider where the nameserver hostname is NXDOMAIN — full domain takeover risk), `"mx_dangling:<mx_host>"` (MX record points to a hostname that doesn't resolve — potential mail interception), `"domain_expired"` (RDAP shows the domain registration has expired), `"domain_expiring_soon:<N>d"` (domain expires within 60 days — potential lapse risk), `"domain_status:<status>"` (domain has a risky ICANN status like `pendingDelete`, `redemptionPeriod`, `serverHold`, `clientHold`, or `pendingTransfer`), `"no_dnssec"` (domain does not have DNSSEC delegation signing active), `"cert_expired"` (live TLS certificate has expired), `"cert_expiring_soon:<N>d"` (certificate expires within 30 days), `"cert_self_signed"` (certificate issuer matches subject — self-signed), `"cors_wildcard_credentials"` (CORS allows all origins with credentials — credential theft risk), `"cookies_missing_secure"` (at least one cookie missing the Secure flag — sent over HTTP), `"cookies_missing_httponly"` (at least one cookie missing HttpOnly — accessible via JavaScript), `"http_auth_required:<code>"` (returned 401 or 403 — auth-protected resource), `"http_server_error:<code>"` (returned 500/502/503 — misconfigured or failing), `"http_not_found:<code>"` (returned 404), `"http_redirect_permanent:<code>"` (returned 301/308), `"version_disclosed:<header>"` (a response header contains a version string, e.g. `"version_disclosed:server"`, `"version_disclosed:x-powered-by"`), `"sans_new_subdomains"` (host's TLS certificate SANs contain FQDNs not present in the store — potential undiscovered subdomains worth investigating). |
| `takeover_candidate` | bool | `true` if any `takeover:*` or `ns_takeover_risk:*` flag was set. Quick filter for high-priority findings. |
| `notes` | string or null | Free-text field for additional context. |

### Flag severity ratings

Each flag is assigned a severity level. The host's `analysis.severity` field reflects the highest severity among its flags.

| Severity | Flags |
|---|---|
| **critical** | `takeover:*`, `ns_takeover_risk:*`, `domain_expired`, `cert_expired`, `domain_status:pendingDelete`, `domain_status:redemptionPeriod` |
| **high** | `stale_cname`, `mx_dangling:*`, `domain_expiring_soon:*`, `cert_expiring_soon:*`, `domain_status:serverHold`, `domain_status:clientHold`, `spf_permissive`, `private_ip_external` |
| **medium** | `geo_mismatch:*`, `multiple_apex_owners`, `unexpected_asn:*`, `cert_self_signed`, `cors_wildcard_credentials`, `domain_status:pendingTransfer`, `lower_env_exposed` |
| **low** | `no_dnssec`, `cookies_missing_secure`, `cookies_missing_httponly`, `version_disclosed:*`, `http_server_error:*`, `http_auth_required:*`, `http_not_found:*`, `http_redirect_permanent:*`, `wildcard_dns`, `sans_new_subdomains` |

### rdap (RdapInfo)

Populated by `rp rdap`. Contains RDAP registration data queried once per apex domain and shared across all hosts under that apex.

| Field | Type | Description |
|---|---|---|
| `registrar` | string or null | The domain registrar (e.g. `"Cloudflare, Inc."`, `"GoDaddy.com, LLC"`). Useful for correlating infrastructure ownership. |
| `registered_at` | string or null | ISO 8601 timestamp of when the domain was first registered. |
| `expires_at` | string or null | ISO 8601 timestamp of when the domain registration expires. Domains expiring soon are flagged by analyze. |
| `statuses` | list | ICANN domain status codes (e.g. `["clientTransferProhibited", "clientDeleteProhibited"]`). Statuses like `pendingDelete`, `redemptionPeriod`, `serverHold`, or `clientHold` indicate domains in risky transition states. |
| `nameservers` | list | Nameservers registered with the registry (as opposed to what DNS resolves). Differences between these and `dns.ns` can indicate stale delegation. |
| `dnssec` | bool or null | Whether DNSSEC delegation signing is active. `false` means the domain is not DNSSEC-signed. `null` if the RDAP response didn't include this field. |
| `queried_at` | string | ISO 8601 timestamp of when the RDAP lookup was performed. |

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
rpq | jq 'select(.fqdn == "shop.example.com")'
```

**Look up a specific IP (any host resolving to it):**
```bash
rpq | jq 'select(.dns.resolved_ips[]?.ip == "198.51.100.10")'
```

**Look up multiple subdomains:**
```bash
rpq | jq 'select(.fqdn == "shop.example.com" or .fqdn == "api.example.com")'
```

**Look up multiple IPs:**
```bash
rpq | jq 'select([.dns.resolved_ips[]?.ip] | any(. == "203.0.113.50" or . == "198.51.100.10"))'
```

**Partial/pattern match on FQDN:**
```bash
# All subdomains containing "shop"
rpq | jq 'select(.fqdn | test("shop"))'

# All subdomains starting with "api"
rpq | jq 'select(.fqdn | test("^api\\."))'

# All subdomains under a specific subdomain tree
rpq | jq 'select(.fqdn | endswith(".dev.example.com"))'
```

**Search by IP subnet/prefix:**
```bash
# All hosts on 203.0.x.x
rpq | jq 'select([.dns.resolved_ips[]?.ip // empty] | any(test("^203\\.0\\.")))'
```

### Header analysis queries

**Hosts where url_checked doesn't match the FQDN (redirect/CNAME mismatch):**
```bash
rpq | jq '.fqdn as $f | select(.headers != null and (.headers.url_checked | contains($f) | not))'
```

**Hosts where the FQDN appears in url_checked (no mismatch):**
```bash
rpq | jq '.fqdn as $f | select(.headers != null and (.headers.url_checked | contains($f)))'
```

**Hosts missing a specific security header:**
```bash
# Missing HSTS
rpq | jq 'select(.headers != null and ([.headers.missing[]?] | any(. == "Strict-Transport-Security")))'

# Missing multiple specific headers
rpq | jq 'select(.headers != null and ([.headers.missing[]?] | any(. == "Strict-Transport-Security" or . == "X-Content-Type-Options")))'
```

**Hosts with a specific status code:**
```bash
rpq | jq 'select(.headers != null and .headers.status_code == 403)'
```

**Hosts behind a specific server (e.g. Cloudflare):**
```bash
rpq | jq 'select(.headers.present.server? // "" | test("cloudflare"; "i"))'
```

**Hosts with version disclosure (any header leaking a version string):**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("version_disclosed")))'
```

**Version disclosure excluding specific headers (e.g. error reference IDs):**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("version_disclosed") and (test("x-reference-error") | not)))'
```

**Extract just the server value from version-disclosing hosts:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("version_disclosed") and (test("x-reference-error") | not))) | .headers.present.server'
```

**Hosts with a specific X- header present:**
```bash
rpq | jq 'select(.headers.present["x-powered-by"]? != null)'
rpq | jq 'select(.headers.present["x-aspnet-version"]? != null)'
```

**List all X- headers across the entire store:**
```bash
rpq | jq -r '[.headers.present // {} | keys[] | select(startswith("x-"))] | .[]' | sort -u
```

**Hosts returning server errors:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("http_server_error")))'
```

**Hosts requiring authentication:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("http_auth_required")))'
```

### Page title and technology queries

**Hosts with a specific page title:**
```bash
rpq | jq 'select(.headers.page_title? // "" | test("Jenkins"; "i"))'
rpq | jq 'select(.headers.page_title? // "" | test("login|sign in"; "i"))'
```

**Hosts where a specific technology was detected:**
```bash
rpq | jq 'select([.headers.technologies[]?] | any(. == "WordPress"))'
rpq | jq 'select([.headers.technologies[]?] | any(. == "Jenkins"))'
```

**List all detected technologies across the store:**
```bash
rpq | jq -r '.headers.technologies[]?' | sort | uniq -c | sort -rn
```

**Hosts with a meta generator tag:**
```bash
rpq | jq 'select(.headers != null and .headers.meta_generator != null) | {fqdn, generator: .headers.meta_generator}'
```

### Cookie and CORS queries

**Hosts setting cookies without Secure flag:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "cookies_missing_secure"))'
```

**Hosts with CORS wildcard + credentials:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "cors_wildcard_credentials"))'
```

**List all cookies and their security attributes:**
```bash
rpq | jq 'select(.headers != null and (.headers.cookies | length > 0)) | {fqdn, cookies: .headers.cookies}'
```

### TLS certificate queries

**Hosts with expired certificates:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("cert_expired")))'
```

**Hosts with self-signed certificates:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "cert_self_signed"))'
```

**Certificates expiring soon:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("cert_expiring_soon")))'
```

**Hosts by certificate issuer:**
```bash
rpq | jq -r 'select(.tls != null) | .tls.issuer_org // "unknown"' | sort | uniq -c | sort -rn
```

**Find additional domains from certificate SANs:**
```bash
rpq | jq -r '.tls.sans[]?' | sort -u
```

**Certificates issued by a specific CA:**
```bash
rpq | jq 'select(.tls.issuer_org? // "" | test("Let.s Encrypt"; "i"))'
```

**Hosts with TLS SANs containing undiscovered subdomains:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "sans_new_subdomains"))'
```

**Exposed lower environments (dev/staging/qa/uat/test/sandbox/preprod):**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "lower_env_exposed"))'
```

**Lower environments with details (fqdn, title, status code):**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "lower_env_exposed")) | {fqdn, title: .headers.page_title, status: .headers.status_code, technologies: .headers.technologies}'
```

### Redirect chain queries

**Hosts that redirected (with full redirect chain):**
```bash
rpq | jq 'select(.headers != null and (.headers.redirect_chain | length > 0)) | {fqdn, chain: .headers.redirect_chain}'
```

**Find all unique redirect destinations (useful for building redirect-deny lists):**
```bash
rpq | jq -r 'select(.headers != null) | .headers.redirect_chain[-1]? // empty' | sort -u
```

**Count hosts per redirect destination (find mass-redirect patterns):**
```bash
rpq | jq -r 'select(.headers != null) | .headers.redirect_chain[-1]? // empty' | sort | uniq -c | sort -rn | head -20
```

**Hosts redirecting to a specific domain:**
```bash
rpq | jq 'select(.headers != null and ([.headers.redirect_chain[]?] | any(test("microsoftonline.com"))))'
rpq | jq 'select(.headers != null and ([.headers.redirect_chain[]?] | any(test("okta.com"))))'
```

**Hosts redirecting off-domain (final URL doesn't contain the original FQDN):**
```bash
rpq | jq '.fqdn as $f | select(.headers != null and (.headers.redirect_chain | length > 0) and (.headers.redirect_chain[-1] | contains($f) | not)) | {fqdn, final: .headers.redirect_chain[-1]}'
```

**Hosts with long redirect chains (3+ hops):**
```bash
rpq | jq 'select(.headers != null and (.headers.redirect_chain | length >= 3)) | {fqdn, hops: (.headers.redirect_chain | length), chain: .headers.redirect_chain}'
```

**HTTP-to-HTTPS redirects (initial hop is HTTP, lands on HTTPS):**
```bash
rpq | jq 'select(.headers != null and (.headers.redirect_chain | length > 0) and (.headers.redirect_chain[0] | test("^http://")) and (.headers.redirect_chain[-1] | test("^https://")))'
```

### Body snippet queries

**Search response bodies for a keyword:**
```bash
rpq | jq 'select(.headers.body_snippet? // "" | test("password"; "i")) | .fqdn'
rpq | jq 'select(.headers.body_snippet? // "" | test("api[_-]?key"; "i")) | .fqdn'
```

**Hosts with error messages in the body:**
```bash
rpq | jq 'select(.headers.body_snippet? // "" | test("stack trace|exception|traceback|debug"; "i")) | {fqdn, title: .headers.page_title}'
```

**Hosts with login/auth pages:**
```bash
rpq | jq 'select(.headers.body_snippet? // "" | test("login|sign.in|username|password"; "i")) | {fqdn, title: .headers.page_title, status: .headers.status_code}'
```

**Hosts with directory listings:**
```bash
rpq | jq 'select(.headers.body_snippet? // "" | test("Index of /|directory listing|Parent Directory"; "i")) | .fqdn'
```

**Hosts exposing environment or config details:**
```bash
rpq | jq 'select(.headers.body_snippet? // "" | test("DATABASE_URL|REDIS_URL|SECRET_KEY|AWS_ACCESS"; "i")) | .fqdn'
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

**Hosts with TXT records:**
```bash
rpq | jq 'select(.dns.txt | length > 0)'
```

**Hosts with a specific string in TXT records (e.g. SPF, verification tokens):**
```bash
rpq | jq 'select([.dns.txt[]?] | any(test("v=spf1")))'
rpq | jq 'select([.dns.txt[]?] | any(test("google-site-verification")))'
rpq | jq 'select([.dns.txt[]?] | any(test("MS=")))'
rpq | jq 'select([.dns.txt[]?] | any(test("aws")))'
```

**Hosts with MX records (accepting mail):**
```bash
rpq | jq 'select(.dns.mx | length > 0)'
```

**Hosts using a specific mail provider:**
```bash
rpq | jq 'select([.dns.mx[]?] | any(test("google"; "i")))'
rpq | jq 'select([.dns.mx[]?] | any(test("outlook"; "i")))'
```

**Hosts with NS records:**
```bash
rpq | jq 'select(.dns.ns | length > 0)'
```

**Hosts delegated to a specific DNS provider:**
```bash
rpq | jq 'select([.dns.ns[]?] | any(test("cloudflare")))'
rpq | jq 'select([.dns.ns[]?] | any(test("awsdns")))'
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

**IPs with reverse DNS (PTR) records:**
```bash
rpq | jq -r '[.dns.resolved_ips[]? | select(.ptr != null) | "\(.ip) \(.ptr)"] | .[]'
```

**All unique PTR hostnames across the store:**
```bash
rpq | jq -r '.dns.resolved_ips[]?.ptr // empty' | sort -u
```

### Analysis and flag queries

**Hosts by severity level:**
```bash
# All critical findings
rpq | jq 'select(.analysis.severity == "critical")'

# Critical and high findings
rpq | jq 'select(.analysis.severity == "critical" or .analysis.severity == "high")'

# Medium and above
rpq | jq 'select(.analysis.severity != null and .analysis.severity != "low")'

# Count hosts per severity
rpq | jq -r '.analysis.severity // "none"' | sort | uniq -c | sort -rn

# Summary table: fqdn, severity, flags
rpq | jq 'select(.analysis.severity != null) | {fqdn, severity: .analysis.severity, flags: .analysis.flags}'
```

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

**SPF permissive (spoofable mail domains):**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "spf_permissive"))'
```

**NS delegation takeover risks:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("ns_takeover_risk")))'
```

**Dangling MX records:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("mx_dangling")))'
```

**Hosts on an unexpected ASN (outlier within their apex):**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("unexpected_asn")))'
```

**Domains expiring soon or expired:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("domain_expir")))'
```

**Domains with risky ICANN statuses (pendingDelete, serverHold, etc.):**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(test("domain_status")))'
```

**Domains without DNSSEC:**
```bash
rpq | jq 'select([.analysis.flags[]?] | any(. == "no_dnssec"))'
```

### RDAP queries

**Hosts with RDAP data:**
```bash
rpq | jq 'select(.rdap != null)'
```

**Domains by registrar:**
```bash
rpq | jq -r 'select(.rdap != null) | .rdap.registrar // "unknown"' | sort | uniq -c | sort -rn
```

**Domains expiring within 90 days (raw RDAP field):**
```bash
rpq | jq 'select(.rdap.expires_at != null) | {fqdn, apex, expires: .rdap.expires_at}'
```

**Compare RDAP nameservers vs DNS NS records:**
```bash
rpq | jq 'select(.rdap != null and .dns.ns != null and (.dns.ns | length > 0)) | {fqdn, dns_ns: .dns.ns, rdap_ns: .rdap.nameservers}'
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
rpq | jq 'select([.discovery_sources[]?] | any(test("crtsh")))'
rpq | jq 'select([.discovery_sources[]?] | any(test("bbot")))'
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
rpq | jq '.fqdn as $f | select(
  ([.discovery_sources[]?] | any(test("crtsh"))) and
  .headers != null and
  (.headers.url_checked | contains($f) | not)
)'
```

### Infrastructure mapping

**Group hosts by ASN (see which networks are in use):**
```bash
rpq | jq -r '.dns.resolved_ips[]? | select(.asn != null) | "\(.asn)\t\(.asn_org // "unknown")"' | sort -u | sort -t$'\t' -k1 -n
```

**Count hosts per ASN org:**
```bash
rpq | jq -r '[.dns.resolved_ips[]? | select(.asn_org != null) | .asn_org] | unique[]' | sort | uniq -c | sort -rn
```

**Count hosts per country:**
```bash
rpq | jq -r '[.dns.resolved_ips[]? | select(.country != null) | .country] | unique[]' | sort | uniq -c | sort -rn
```

**Hosts sharing the same IP (co-hosted/virtual hosts):**
```bash
rpq | jq -r '.dns.resolved_ips[]?.ip' | sort | uniq -c | sort -rn | awk '$1 > 1' | while read count ip; do echo "=== $ip ($count hosts) ==="; rpq | jq -r "select([.dns.resolved_ips[]?.ip] | any(. == \"$ip\")) | .fqdn"; done
```

**Map IP to all FQDNs, PTR, and ASN (full IP context):**
```bash
rpq | jq -r '[.dns.resolved_ips[]? | select(.ip != null) | "\(.ip)\t\(.ptr // "-")\t\(.asn_org // "-")"] | .[]' | sort -u -t$'\t' -k1,1
```

**CNAME chain providers — what third-party services are in use:**
```bash
rpq | jq -r '.dns.cname_chain[]?' | sed 's/.*\.\([^.]*\.[^.]*\)$/\1/' | sort | uniq -c | sort -rn
```

**Hosts per registrar (via RDAP):**
```bash
rpq | jq -r 'select(.rdap != null) | "\(.apex)\t\(.rdap.registrar // "unknown")"' | sort -u -t$'\t' -k2 | cut -f2 | uniq -c | sort -rn
```

**Hosts per TLS issuer org:**
```bash
rpq | jq -r 'select(.tls != null) | .tls.issuer_org // "unknown"' | sort | uniq -c | sort -rn
```

**Wildcard vs single-domain certificates:**
```bash
rpq | jq 'select(.tls != null) | {fqdn, subject: .tls.subject, san_count: (.tls.sans | length), wildcard: ([.tls.sans[]? | select(startswith("*."))] | length > 0)}'
```

### Cross-field hunting

**Hosts with login pages that are missing security headers:**
```bash
rpq | jq 'select(
  .headers != null and
  (.headers.page_title? // "" | test("login|sign.in|auth"; "i")) and
  (.headers.missing | length > 2)
) | {fqdn, title: .headers.page_title, missing: .headers.missing}'
```

**Lower environments with cookies missing Secure flag:**
```bash
rpq | jq 'select(
  ([.analysis.flags[]?] | any(. == "lower_env_exposed")) and
  ([.analysis.flags[]?] | any(. == "cookies_missing_secure"))
) | {fqdn, title: .headers.page_title, flags: .analysis.flags}'
```

**Hosts on non-CDN ASNs with self-signed certs (likely internal services):**
```bash
rpq | jq 'select(
  ([.analysis.flags[]?] | any(. == "cert_self_signed")) and
  ([.dns.resolved_ips[]? | select(.asn != null) | .asn] | all(. != 13335 and . != 54113 and . != 20940 and . != 16509))
) | {fqdn, asn_org: .dns.resolved_ips[0].asn_org, subject: .tls.subject}'
```

**Hosts responding 200 with no CNAME (direct infrastructure, not behind CDN):**
```bash
rpq | jq 'select(
  .headers.status_code == 200 and
  (.dns.cname_chain | length == 0) and
  .dns.resolved_ips[0].asn_org != null
) | {fqdn, ip: .dns.resolved_ips[0].ip, asn_org: .dns.resolved_ips[0].asn_org}'
```

**Hosts where RDAP nameservers differ from live DNS NS:**
```bash
rpq | jq 'select(.rdap != null and .dns.ns != null and (.dns.ns | length > 0)) | 
  .dns.ns as $live | .rdap.nameservers as $rdap |
  select(($live | sort) != ($rdap | sort)) |
  {fqdn, live_ns: $live, rdap_ns: $rdap}'
```

**Stale CNAMEs pointing to specific providers:**
```bash
rpq | jq 'select(
  ([.analysis.flags[]?] | any(. == "stale_cname"))
) | {fqdn, chain: .dns.cname_chain, ips: [.dns.resolved_ips[]?.ip]}'
```

**Hosts with both version disclosure and server errors:**
```bash
rpq | jq 'select(
  ([.analysis.flags[]?] | any(test("version_disclosed"))) and
  ([.analysis.flags[]?] | any(test("http_server_error")))
) | {fqdn, server: .headers.present.server, status: .headers.status_code}'
```

**Unique SAN domains not in the store (potential attack surface):**
```bash
rpq | jq -r '.tls.sans[]?' | sort -u | while read san; do
  san_clean=$(echo "$san" | sed 's/^\*\.//')
  rpq | jq -r '.fqdn' | grep -qx "$san_clean" || echo "$san_clean"
done
```

**Hosts discovered only by one source (not cross-validated):**
```bash
rpq | jq 'select(.discovery_sources | length == 1) | {fqdn, source: .discovery_sources[0]}'
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

### Diff workflows

```bash
# Compare two scans
rp diff --old scan1.jsonl --new scan2.jsonl

# JSON output for programmatic use
rp diff --old scan1.jsonl --new scan2.jsonl --format json

# CSV for spreadsheets
rp diff --old scan1.jsonl --new scan2.jsonl --format csv

# Include all scope buckets
rp diff --old scan1.jsonl --new scan2.jsonl --scope all
```

### Redirect-deny workflow

After `rp headers`, identify mass-redirect patterns and filter them out:

```bash
# 1. Find the most common redirect destinations
rpq | jq -r 'select(.headers != null) | .headers.redirect_chain[-1]? // empty' | sort | uniq -c | sort -rn | head -20

# 2. Create a redirect-deny file with the noisy destinations
cat > redirect-deny.txt <<EOF
login.microsoftonline.com
parked.example.com
re:.*\.parked-domain\.com
EOF

# 3. Re-run scope with redirect-deny
rp scope -i /tmp/store.jsonl --allow allow.txt --deny deny.txt --redirect-deny redirect-deny.txt

# 4. Verify what got filtered
rp report --view combined --scope out -i /tmp/store.jsonl | jq 'select(.scope.matched_rule | test("redirect-deny")) | {fqdn, rule: .scope.matched_rule}'
```

### Feeding other tools

```bash
# Feed live IPs to nmap
rp report -i /tmp/store.jsonl --view ips -o live-ips.txt
nmap -iL live-ips.txt -sV -oA scan

# Feed in-scope subdomains to other tools
rp report -i /tmp/store.jsonl --view subs --scope in -o inscope-subs.txt

# Extract URLs for web scanning (httpx/nuclei/etc.)
rpq | jq -r 'select(.headers != null and .headers.url_checked != "") | .headers.url_checked' > live-urls.txt

# Extract hosts with specific technologies for targeted scanning
rpq | jq -r 'select([.headers.technologies[]?] | any(. == "WordPress")) | .headers.url_checked' > wordpress-targets.txt
rpq | jq -r 'select([.headers.technologies[]?] | any(. == "Jenkins")) | .headers.url_checked' > jenkins-targets.txt

# Export flagged hosts as CSV for reporting
rp report -i /tmp/store.jsonl --view combined --flagged-only --format csv -o flagged.csv

# Extract all unique IPs with their PTR and ASN for network mapping
rpq | jq -r '.dns.resolved_ips[]? | select(.ip != null) | [.ip, .ptr // "", .asn // "", .asn_org // "", .country // ""] | @csv' | sort -u > ip-intel.csv
```

### Quick triage

```bash
# One-liner: severity breakdown
rpq | jq -r '.analysis.severity // "clean"' | sort | uniq -c | sort -rn

# One-liner: flag breakdown
rpq | jq -r '.analysis.flags[]?' | sort | uniq -c | sort -rn

# One-liner: how many hosts have data from each module
rpq | jq -r '[
  (if .dns != null then "dns" else empty end),
  (if .headers != null then "headers" else empty end),
  (if .tls != null then "tls" else empty end),
  (if .rdap != null then "rdap" else empty end),
  (if .analysis != null then "analyze" else empty end)
] | .[]' | sort | uniq -c | sort -rn

# One-liner: technology breakdown
rpq | jq -r '.headers.technologies[]?' | sort | uniq -c | sort -rn

# Top 10 page titles (quick overview of what's running)
rpq | jq -r '.headers.page_title? // empty' | sort | uniq -c | sort -rn | head -10

# Hosts with no data at all (enum only, nothing else ran)
rpq | jq 'select(.dns == null and .headers == null and .tls == null) | .fqdn'
```
