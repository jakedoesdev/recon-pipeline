# Recon Pipeline — Design Doc

## Purpose

A composable recon tool that runs the repetitive front-half of a web/external assessment against a list of in-scope domains: subdomain enumeration, DNS resolution with private-IP flagging, security header checks, scope filtering, and basic DNS sanity (stale records, geo mismatches, takeover indicators). The same artifact powers several output views — bare subdomain list, bare IP list, subs-with-IPs, header report, and a combined record showing every fact known about each host along with its discovery sources.

The design priority is composability and stability over feature breadth. Each phase should be runnable in isolation, idempotent, and round-trip through a single canonical on-disk format so re-runs and partial re-runs don't lose prior work.

## Non-goals

- Active exploitation, scanning past TCP/443 fetch, or vulnerability checks beyond header analysis. Nessus/Nuclei stay outside this tool.
- Live UI. CLI only.
- Replacing BBOT. This wraps BBOT, it doesn't reimplement it.

## Architecture

Python 3.11+ package with a Click-based CLI exposing subcommands. Each subcommand reads and writes a JSON Lines file as the canonical intermediate format. One record per FQDN. Records accumulate fields as each phase runs — `enum` adds discovery sources, `resolve` adds IPs and record types, `headers` adds the header check, `scope` adds in/out flag, `analyze` adds anomaly flags. `report` is a pure read that emits the various output views.

Recommended name: `reconpipe` (binary: `rp`). Open to alternatives.

Layout:

```
reconpipe/
├── pyproject.toml
├── reconpipe/
│   ├── cli.py            # Click root + subcommand registration
│   ├── models.py         # Host dataclass, IO helpers
│   ├── store.py          # JSONL read/write, dedup-merge on FQDN
│   ├── enum/
│   │   ├── bbot.py       # BBOT subprocess wrapper, output parser, BBOT secrets YAML writer
│   │   └── crtsh.py      # crt.sh JSON client with retry
│   ├── presets/          # BBOT preset YAML files shipped with the package
│   │   └── reconpipe-quiet.yml
│   ├── resolve.py        # dnspython resolver, CNAME chain walk, private detection
│   ├── headers.py        # native header fetch + optional securityheaders.com lookup
│   ├── scope.py          # allow/deny list matching
│   ├── analyze.py        # takeover fingerprints, geo/ASN sanity
│   └── report.py         # output formatters
└── tests/
```

## Canonical record (models.py)

One JSONL line per FQDN. Fields are additive — phases that haven't run yet leave their fields null.

```python
@dataclass
class Host:
    fqdn: str                              # normalized lowercase, no trailing dot
    apex: str                              # registered domain via tldextract
    discovery_sources: list[str]           # ["bbot:subdomain_enum", "crtsh", "manual"]
    first_seen: str                        # ISO-8601
    last_updated: str
    dns: DnsInfo | None
    headers: HeaderInfo | None
    scope: ScopeInfo | None
    analysis: AnalysisInfo | None

@dataclass
class DnsInfo:
    a: list[str]
    aaaa: list[str]
    cname_chain: list[str]                 # [target1, target2, ...] full chain
    resolved_ips: list[ResolvedIp]         # flattened, with provenance
    nxdomain: bool
    resolver_used: str
    resolved_at: str

@dataclass
class ResolvedIp:
    ip: str
    record_type: str                       # "A" | "AAAA" | "CNAME->A"
    is_private: bool                       # RFC 1918, CGNAT, link-local, loopback
    asn: int | None
    asn_org: str | None
    country: str | None                    # ISO 3166-1 alpha-2

@dataclass
class HeaderInfo:
    url_checked: str                       # which scheme/host actually responded
    status_code: int
    present: dict[str, str]                # header -> value (truncated)
    missing: list[str]                     # from a configurable expected set
    source: str                            # "native" | "securityheaders" | "securityheaders_then_native"
    grade: str | None                      # only populated if securityheaders.com succeeded
    checked_at: str

@dataclass
class ScopeInfo:
    status: str                            # "in" | "out" | "unmatched"
    matched_rule: str | None               # which allow/deny rule decided, null when unmatched
    warning: str | None                    # populated when status == "unmatched"

@dataclass
class AnalysisInfo:
    flags: list[str]                       # "stale_cname", "geo_mismatch:CN", "takeover:s3", "private_ip"
    takeover_candidate: bool
    notes: str | None
```

Store helpers must merge by `fqdn` on every write — never overwrite, always union `discovery_sources` and refresh phase fields if the new write has them.

## Subcommands

### `rp enum`

Inputs:
- `-i INPUT` — file of root domains, one per line (e.g. `acme.com`, `acme.io`)
- `--bbot/--no-bbot` — default on
- `--bbot-preset` — one of `kitchen-sink`, `subdomain-enum`, `reconpipe-quiet` (default `reconpipe-quiet`)
- `--bbot-args` — raw passthrough for power use, appended after the preset flag
- `--crtsh/--no-crtsh` — default on
- `-o OUTPUT` — JSONL path; appends/merges if exists

BBOT presets:
- `kitchen-sink` — invokes `bbot -t <targets> -p kitchen-sink`. Wide and loud; appropriate when scope explicitly allows aggressive enumeration.
- `subdomain-enum` — invokes `bbot -t <targets> -p subdomain-enum`. The standard mix of passive sources plus DNS bruteforce.
- `reconpipe-quiet` (default) — invokes `bbot -t <targets> -p <path-to-presets/reconpipe-quiet.yml>`. Ships with the package. Extends `subdomain-enum` and disables the noisy/slow modules: `massdns`, `dnsbrute`, `dnsbrute_mutations`, `ffuf`, `ffuf_shortnames`, `iis_shortnames`, `ntlm`, `paramminer_*`, `wafw00f`, `gowitness`, `nuclei`, `baddns` (active variants), and any module flagged `aggressive` or `slow` in BBOT's module flags. Goal: passive sources and light DNS only, suitable for early-engagement recon where you don't yet know the client's posture.

Passive sources beyond crt.sh (Shodan, SecurityTrails, VirusTotal, URLScan, Chaos, etc.) are accessed exclusively through BBOT. Their API keys live in `keys.toml` and the BBOT wrapper exports them on invocation — `reconpipe` does not call those APIs directly.

Behavior:
- BBOT wrapper writes a tmp BBOT secrets YAML from `keys.toml` (so BBOT's modules see the keys without separate setup), then invokes the chosen preset with `-o <tmpdir> --silent` and parses the resulting `output.ndjson` (preferred — per-finding module attribution) or falls back to flat `subdomains.txt`. `discovery_sources` records `bbot:<module>` from ndjson, or `bbot:<preset>` from the flat fallback.
- crt.sh client hits `https://crt.sh/?q=%.<domain>&output=json` with retries (it 502s often), deduplicates `name_value` entries (split on `\n`, strip `*.`), and tags each with `crtsh`.
- BBOT and crt.sh run concurrently per target.
- Output is appended to the JSONL store, merging on FQDN. A subdomain found by both BBOT (via, say, the shodan_dns module) and crt.sh ends up with `["bbot:shodan_dns", "crtsh"]` in `discovery_sources`.

### `rp resolve`

Inputs:
- `-i INPUT` — JSONL (or plain txt; auto-detect by first-line shape)
- `--resolvers` — comma list, defaults to `1.1.1.1,8.8.8.8,9.9.9.9`
- `--asn-db` — optional MaxMind GeoLite2 ASN mmdb path
- `--country-db` — optional MaxMind GeoLite2 Country mmdb path
- `--wildcard-detect/--no-wildcard-detect` — default on. When enabled, resolves 3 randomly-generated labels under each apex before processing hosts under that apex. If all 3 return identical A records, the apex is marked wildcarded; every host that resolves to that same A gets `wildcard_dns` added to its analysis flags so the IP attribution is known to be unreliable. Adds 3 extra queries per apex, but apex-level so the cost is bounded.
- `--concurrency` — default 50

Behavior:
- For each FQDN, query A, AAAA, and CNAME with dnspython. Walk CNAME chains up to a sane depth limit (10). Record the full chain.
- Flatten to `resolved_ips`. Set `is_private` via `ipaddress.ip_address(x).is_private or is_link_local or is_loopback`.
- If ASN/country DBs are configured, populate them. If not, leave null — `analyze` can fall back to a free API later if invoked with `--enrich-online`.
- NXDOMAIN, SERVFAIL, and timeout are distinct outcomes — record them. A timeout shouldn't get marked NXDOMAIN.

### `rp headers`

Inputs:
- `-i INPUT` — JSONL
- `--scheme` — `https` (default), `http`, or `both`
- `--source` — `native` (default), `securityheaders`, or `both`
- `--timeout` — default 10s
- `--user-agent` — configurable; default a generic Firefox UA
- `--expected` — path to a file listing expected headers; default built-in set: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`

Behavior:
- Native mode (default): direct fetch against each FQDN. HEAD then GET fallback (some sites strip headers on HEAD). Record status, capture every header in the expected set, plus `Server` and `X-Powered-By` if present. Truncate values at 200 chars. Set `source="native"`.
- securityheaders mode: hit `https://securityheaders.com/?q=<url>&hide=on&followRedirects=on` (unauthenticated scrape). Retry up to 3 times with exponential backoff on 429/5xx/timeout. If all 3 attempts fail, fall back to native mode for that host and set `source="securityheaders_then_native"`. On success, parse the grade from the `X-Score` response header. Rate-limit globally at 1 req/sec to be a polite scraper.
- `both`: run native first (cheap), then securityheaders on top so the record has the grade as well as the raw header values. If securityheaders fails 3x, that host just keeps its native result.
- Skip FQDNs that didn't resolve in the prior `resolve` phase unless `--force`.

### `rp scope`

Inputs:
- `-i INPUT` — JSONL
- `--allow` — file with in-scope patterns (one per line)
- `--deny` — file with out-of-scope patterns (one per line)

Pattern syntax: exact match (`api.acme.com`), wildcard subdomain (`*.acme.com`), or regex prefixed with `re:`. Deny rules take precedence over allow rules.

Resolution:
- Matches a deny rule → `status="out"`, `matched_rule="deny:<pattern>"`.
- Matches an allow rule (and no deny) → `status="in"`, `matched_rule="allow:<pattern>"`.
- Matches neither → `status="unmatched"`, `warning="No allow/deny rule covers this host; defaulted unmatched. Review and update scope lists."`.

Fail-open: unmatched hosts are kept in the dataset and continue through `resolve`, `headers`, and `analyze`. But they are **never** rolled in with `status="in"` in any report view — `unmatched` is its own bucket that the operator reviews and triages (typically by adding to allow or deny and re-running `rp scope`).

Behavior: pure tagging step. Doesn't drop hosts from the store.

### `rp analyze`

Inputs:
- `-i INPUT` — JSONL
- `--expected-country` — ISO code (e.g. `US`); flag any resolved IP whose country differs
- `--takeover-fingerprints` — path to a fingerprints file; default ships with embedded set covering S3, Azure Blob, Heroku, GitHub Pages, Shopify, Fastly, Unbounce, Tumblr, Pantheon, etc. (model after can-i-take-over-xyz; cite source in README)
- `--enrich-online/--no-enrich-online` — when ASN/country aren't populated from MaxMind DBs, fall back to `ipinfo.io` using the key from `keys.toml`. Off by default to keep the tool offline-capable.

Checks:
- `stale_cname` — CNAME chain ends in NXDOMAIN
- `takeover:<service>` — CNAME chain hits a known takeover fingerprint and the target appears unclaimed (HTTP fetch returns the service's "no such bucket / app not found" body)
- `geo_mismatch:<cc>` — at least one resolved IP's country != `--expected-country`
- `private_ip_external` — host has a public DNS record but resolves to RFC 1918 space (worth a look — often misconfiguration leaking internal IPs)
- `wildcard_dns` — set by `resolve` when the apex is wildcarded; preserved here as a known caveat on every IP attribution under that apex
- `ipv6_only` / `ipv4_only` — informational
- `multiple_apex_owners` — different IPs across the same apex resolve to wildly different ASNs (rough heuristic for stale/hijacked records)

Ordering: takeover and stale-CNAME checks fire before geo-mismatch, since geo on a third-party CNAME target isn't a meaningful signal about the client.

### `rp report`

Inputs:
- `-i INPUT` — JSONL
- `--view` — one of:
  - `subs` — bare FQDN list (txt)
  - `ips` — deduped IP list (txt; public only by default; `--include-private` to include)
  - `subs-ips` — CSV: `fqdn,ip,record_type`
  - `headers` — CSV: `fqdn,status,grade,source,missing_headers,present_headers`
  - `combined` — every field known about every host. **Default format: JSONL** (one record per line, ready for `jq`). `--format json-array` emits a single JSON array. `--format csv` flattens to a CSV with `discovery_sources` joined by `|`.
- `--scope` — which scope bucket(s) to include: `in` (default), `unmatched`, `out`, or `all`. Multiple allowed, comma-separated. `unmatched` and `in` are never silently merged — when both are requested, they go to separate files (the `-o` path gets `.in.<ext>` and `.unmatched.<ext>` suffixes).
- `--flagged-only` — filter to hosts with any `analysis.flags`
- `-o OUTPUT` — file path; default stdout
- `--format` — `txt` | `csv` | `json` | `json-array`; defaults per view (`combined` defaults to `json`/JSONL)

Example jq queries (worth putting in the README):

```bash
# Every in-scope host with a stale CNAME
rp report -i store.jsonl --view combined --scope in | \
  jq -c 'select(.analysis.flags // [] | any(. == "stale_cname"))'

# Subdomains discovered only via crt.sh and nowhere else
rp report -i store.jsonl --view combined --scope in | \
  jq -r 'select(.discovery_sources == ["crtsh"]) | .fqdn'

# All public IPs that resolve to a country other than US
rp report -i store.jsonl --view combined --scope in | \
  jq -r '.dns.resolved_ips[]? | select(.is_private == false and .country != "US") | "\(.ip) \(.country)"'
```

### `rp pipeline`

Convenience wrapper that runs `enum → resolve → headers → scope → analyze` in sequence against the same JSONL store. Defaults to the `reconpipe-quiet` BBOT preset to stay polite by default — override with `--bbot-preset` for louder modes. All other flags pass through to each phase. Mostly for one-shot greenfield targets; for ongoing engagements, individual phases are the right granularity.

### `rp diff`

Inputs:
- `--old PATH` — earlier JSONL snapshot
- `--new PATH` — current JSONL snapshot
- `--scope` — which scope buckets to consider, same semantics as `rp report`. Default `in`.
- `-o OUTPUT` — file path; default stdout
- `--format` — `text` (default), `json`, or `csv`

Output: a structured diff with three sections — `added`, `removed`, `changed`. A host is `changed` when any of these shift between snapshots: `dns.resolved_ips`, `dns.cname_chain`, `headers.missing`, `headers.grade`, `scope.status`, `analysis.flags`, or when `discovery_sources` gains a new entry. The diff record includes both the old and new value for every changed field so it's obvious what moved. Text format is meant for quick eyeballing; JSON for piping into other tooling or a triage notebook.

Intended workflow: snapshot the JSONL store after each major recon phase or weekly during a long engagement, then `rp diff` to see what new attack surface appeared, what went away, and what changed posture.

## Operational concerns

**Rate limiting.** crt.sh and securityheaders.com both deserve conservative defaults (1–2 req/sec) with backoff on 429/502. DNS resolution can run wide (50 concurrent is fine against public resolvers); be polite if pointing at a single recursive resolver.

**Resumability.** Every phase reads the JSONL, processes, and writes back via the merging store. Interrupted runs lose only the in-flight host. No separate state file.

**Provenance is sacred.** `discovery_sources` is a union, never overwritten. If a sub shows up first from BBOT and later from crt.sh on a re-run, both end up in the list. Same goes for record-type-level provenance on IPs — a host with an A and a CNAME chain resolving to a different A should keep both with distinct `record_type` values.

**OPSEC.** No telemetry, no analytics. Outbound calls limited to: configured DNS resolvers, BBOT's own modules (whatever BBOT does), crt.sh, securityheaders.com (only when `--source` opts in), the target hosts themselves (headers phase), and any passive API services whose keys are configured. Document the full list in the README so it's auditable against engagement rules.

**Config.** Two files:
- `~/.config/reconpipe/config.toml` — non-secret defaults (resolvers, expected headers, MaxMind DB paths, rate limits, default BBOT preset).
- `~/.config/reconpipe/keys.toml` — API keys, mode `0600`. Loaded only if it exists. Never logged.

Both override-able by env vars (`RECONPIPE_SHODAN_KEY`, etc.) and CLI flags. Precedence: CLI flag > env var > `keys.toml` / `config.toml` > built-in default.

`keys.toml` schema:

```toml
[api_keys]
shodan = ""           # https://account.shodan.io/  — free membership: ~100 query + 100 scan credits/month
securitytrails = ""   # https://securitytrails.com/app/account — free: 50 queries/month, useful for passive DNS history
virustotal = ""       # https://www.virustotal.com/gui/my-apikey — free public API: 4 req/min, 500/day
urlscan = ""          # https://urlscan.io/user/profile/ — free tier, generous limits
chaos = ""            # https://chaos.projectdiscovery.io/ — free with signup, ProjectDiscovery's passive subdomain feed
github = ""           # personal access token (read-only public scope) — passed to BBOT for github_codesearch
ipinfo = ""           # https://ipinfo.io/account — free: 50k requests/month, used for ASN/country enrichment
```

Key routing:
- `shodan`, `securitytrails`, `virustotal`, `urlscan`, `chaos`, `github` — exclusively exported to BBOT via a tmp secrets YAML written on each `bbot` invocation. `reconpipe` itself never calls these APIs directly; if you want their data, run with `--bbot` enabled and let BBOT's modules (`shodan_dns`, `securitytrails`, `virustotal`, `urlscan`, `chaos`, `github_codesearch`, etc.) consume them.
- `ipinfo` — used directly by `resolve` and `analyze --enrich-online` for ASN/country lookup when no MaxMind DB is configured. The only key `reconpipe` calls outside of BBOT.

This keeps the keys auditable in one place while avoiding duplicate implementations of every passive source.

**Logging.** Structured logs to stderr at INFO by default, `-v` for DEBUG. Real output goes to stdout or `-o`.

## Dependencies

- `click` — CLI
- `dnspython` — resolution
- `httpx` — HTTP (sync is fine; supports HTTP/2 if the target speaks it)
- `tldextract` — apex extraction
- `tenacity` — retries/backoff
- `maxminddb` — optional, for offline ASN/country
- `tomli` (or `tomllib` stdlib on 3.11+) — config loading
- `pyyaml` — writing BBOT secrets YAML on invocation
- BBOT — external CLI, called via subprocess (don't pin the Python API; CLI is more stable). Version-pin in README.

## Edge cases worth handling explicitly

- Wildcard DNS — handled by the `--wildcard-detect` flag in `resolve`; the resulting `wildcard_dns` analysis flag is the canonical signal everywhere downstream.
- Internationalized domains — normalize to punycode on ingest.
- IPv6-only hosts — must not crash anything in `headers` or `analyze`. Track separately in reports.
- crt.sh duplicates and noise — heavy deduplication; strip wildcards, lowercase, drop entries with whitespace or invalid chars.
- BBOT's output format has shifted across versions — write the parser against the current ndjson schema and version-pin BBOT in the README install instructions; fall back to flat `subdomains.txt` parsing if ndjson isn't present.
- Hosts that resolve only via CNAME chain ending at a third-party — make sure the discovery source for the chain is preserved and the takeover check fires before the geo check (geo on a third-party IP isn't informative).