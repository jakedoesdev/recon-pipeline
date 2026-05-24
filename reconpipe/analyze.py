from __future__ import annotations

import asyncio
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from .config import get_key
from .fingerprints import BUILTIN_FINGERPRINTS, TakeoverFingerprint
from .log import provenance
from .models import AnalysisInfo, Host, ResolvedIp
from .store import is_out_of_scope, load_store, save_store

logger = logging.getLogger(__name__)

TAKEOVER_FETCH_TIMEOUT = 10
TAKEOVER_CONCURRENCY = 20
DNS_CHECK_CONCURRENCY = 50
IPINFO_CONCURRENCY = 10


def _load_fingerprints(path: str | None) -> list[TakeoverFingerprint]:
    # TODO: support custom fingerprints file
    return BUILTIN_FINGERPRINTS


async def _is_domain_unregistered_async(
    resolver: dns.asyncresolver.Resolver, fqdn: str,
) -> bool:
    import tldextract
    ext = tldextract.extract(fqdn)
    if not ext.domain or not ext.suffix:
        return False
    registrable = f"{ext.domain}.{ext.suffix}"
    for rdtype in ("SOA", "NS"):
        try:
            await resolver.resolve(registrable, rdtype)
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, Exception):
            continue
    return False


def _is_stale_cname_candidate(host: Host) -> str | None:
    """Returns the final CNAME target if it needs an unregistered check, or None."""
    if not host.dns or not host.dns.cname_chain:
        return None
    if host.dns.resolution_error:
        return None
    if not host.dns.resolved_ips and not host.dns.nxdomain:
        return ""
    return host.dns.cname_chain[-1]


async def _batch_stale_cname_checks(
    hosts: dict[str, Host],
) -> set[str]:
    """Returns set of FQDNs that have stale CNAMEs."""
    stale: set[str] = set()
    resolver = dns.asyncresolver.Resolver()
    sem = asyncio.Semaphore(DNS_CHECK_CONCURRENCY)

    targets_needing_dns: list[tuple[str, str]] = []
    for fqdn, host in hosts.items():
        result = _is_stale_cname_candidate(host)
        if result == "":
            stale.add(fqdn)
        elif result is not None:
            targets_needing_dns.append((fqdn, result))

    async def check(fqdn: str, final_target: str) -> None:
        async with sem:
            if await _is_domain_unregistered_async(resolver, final_target):
                stale.add(fqdn)
                provenance(module="analyze", action="stale_cname_confirmed", fqdn=fqdn,
                           cname_target=final_target, unregistered=True)

    tasks = [asyncio.create_task(check(fqdn, target)) for fqdn, target in targets_needing_dns]
    if tasks:
        await asyncio.gather(*tasks)

    return stale


def _check_body_patterns(body: str, fp: TakeoverFingerprint, status_code: int | None = None) -> bool:
    body_lower = body.lower()
    if not any(pattern.lower() in body_lower for pattern in fp.body_patterns):
        return False
    if fp.negative_body_patterns and any(p.lower() in body_lower for p in fp.negative_body_patterns):
        return False
    if fp.negative_status_codes and status_code in fp.negative_status_codes:
        return False
    return True


def _match_takeover_cname(
    host: Host, fingerprints: list[TakeoverFingerprint],
) -> tuple[str | None, list[TakeoverFingerprint]]:
    """Returns (service_if_confirmed, fingerprints_needing_http_fetch).

    Checks NXDOMAIN first, then existing body_snippet from headers.
    Only returns fingerprints needing a live fetch if no stored body is available.
    """
    if not host.dns or not host.dns.cname_chain:
        return None, []

    chain_str = " ".join(host.dns.cname_chain).lower()
    needs_fetch: list[TakeoverFingerprint] = []

    for fp in fingerprints:
        matched_cname = any(pat.lower() in chain_str for pat in fp.cname_patterns)
        if not matched_cname:
            continue
        if fp.nxdomain_vulnerable and not host.dns.resolved_ips and not host.dns.resolution_error:
            return fp.service, []
        if host.headers and host.headers.body_snippet:
            if _check_body_patterns(host.headers.body_snippet, fp, host.headers.status_code):
                return fp.service, []
        else:
            needs_fetch.append(fp)

    return None, needs_fetch


async def _fetch_confirms_takeover_async(
    client: httpx.AsyncClient, fqdn: str, fp: TakeoverFingerprint,
) -> bool:
    for scheme in ("https", "http"):
        try:
            resp = await client.get(f"{scheme}://{fqdn}")
            body = resp.text[:5000]
            if _check_body_patterns(body, fp, resp.status_code):
                provenance(module="analyze", action="takeover_http_confirmed",
                           fqdn=fqdn, service=fp.service, scheme=scheme,
                           status=resp.status_code)
                return True
        except Exception:
            continue
    return False


async def _check_takeovers_async(
    candidates: list[tuple[Host, list[TakeoverFingerprint]]],
) -> dict[str, str]:
    """Returns {fqdn: service} for confirmed takeovers."""
    results: dict[str, str] = {}
    sem = asyncio.Semaphore(TAKEOVER_CONCURRENCY)

    async with httpx.AsyncClient(
        timeout=TAKEOVER_FETCH_TIMEOUT, follow_redirects=True, verify=False,
    ) as client:
        async def check(host: Host, fps: list[TakeoverFingerprint]) -> None:
            async with sem:
                for fp in fps:
                    if await _fetch_confirms_takeover_async(client, host.fqdn, fp):
                        results[host.fqdn] = fp.service
                        return

        tasks = [asyncio.create_task(check(host, fps)) for host, fps in candidates]
        if tasks:
            await asyncio.gather(*tasks)

    return results


def _check_geo_mismatch(host: Host, expected_country: str | None) -> list[str]:
    """Flag IPs whose country differs from expected."""
    if not expected_country or not host.dns:
        return []
    flags = []
    seen_countries: set[str] = set()
    for rip in host.dns.resolved_ips:
        if rip.is_private or not rip.country:
            continue
        if rip.country != expected_country and rip.country not in seen_countries:
            flags.append(f"geo_mismatch:{rip.country}")
            seen_countries.add(rip.country)
    return flags


def _check_private_ip_external(host: Host) -> bool:
    """Public DNS record resolves to RFC 1918 space."""
    if not host.dns or host.dns.nxdomain:
        return False
    return any(rip.is_private for rip in host.dns.resolved_ips)



_NS_TAKEOVER_PATTERNS: list[str] = [
    ".digitalocean.com",
    ".cloudflare.com",
    ".nsone.net",
    ".dnsimple.com",
    ".dnsmadeeasy.com",
    ".no-ip.com",
    ".freedns.afraid.org",
    ".he.net",
    ".linode.com",
    ".vultr.com",
    ".registrar-servers.com",
]


def _check_spf_permissive(host: Host) -> bool:
    if not host.dns or not host.dns.txt:
        return False
    for txt in host.dns.txt:
        lower = txt.lower()
        if "v=spf1" in lower and ("+all" in lower or "?all" in lower):
            return True
    return False


async def _batch_dns_nxdomain_checks(
    hostnames: set[str],
) -> set[str]:
    """Resolve a set of hostnames concurrently. Returns those that are NXDOMAIN."""
    nxdomain: set[str] = set()
    resolver = dns.asyncresolver.Resolver()
    sem = asyncio.Semaphore(DNS_CHECK_CONCURRENCY)

    async def check(hostname: str) -> None:
        async with sem:
            try:
                await resolver.resolve(hostname, "A")
            except dns.resolver.NXDOMAIN:
                nxdomain.add(hostname)
                provenance(module="analyze", action="dns_nxdomain",
                           fqdn=hostname, record_type="A")
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                    dns.exception.Timeout, Exception):
                pass

    tasks = [asyncio.create_task(check(h)) for h in hostnames]
    if tasks:
        await asyncio.gather(*tasks)

    return nxdomain


def _collect_ns_candidates(hosts: dict[str, Host]) -> dict[str, list[str]]:
    """Returns {ns_hostname: [fqdns_using_it]} for NS hostnames matching takeover patterns."""
    ns_to_fqdns: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        if not host.dns or not host.dns.ns:
            continue
        for ns in host.dns.ns:
            ns_lower = ns.lower().rstrip(".")
            for pattern in _NS_TAKEOVER_PATTERNS:
                if ns_lower.endswith(pattern):
                    ns_to_fqdns[ns_lower].append(host.fqdn)
                    break
    return ns_to_fqdns


def _collect_mx_candidates(hosts: dict[str, Host]) -> dict[str, list[str]]:
    """Returns {mx_hostname: [fqdns_using_it]} for all MX hostnames."""
    mx_to_fqdns: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        if not host.dns or not host.dns.mx:
            continue
        for mx_entry in host.dns.mx:
            parts = mx_entry.split()
            mx_host = parts[-1].rstrip(".").lower() if parts else ""
            if mx_host:
                mx_to_fqdns[mx_host].append(host.fqdn)
    return mx_to_fqdns


_STATUS_CATEGORIES: dict[str, list[int]] = {
    "http_auth_required": [401, 403],
    "http_server_error": [500, 502, 503],
    "http_redirect_permanent": [301, 308],
    "http_not_found": [404],
}

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")

_VERSION_SKIP_HEADERS = frozenset({
    "content-security-policy",
    "strict-transport-security",
    "permissions-policy",
    "referrer-policy",
    "cache-control",
    "content-type",
    "content-length",
    "content-encoding",
    "accept-ranges",
    "vary",
    "date",
    "expires",
    "last-modified",
    "etag",
    "age",
    "set-cookie",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-max-age",
})


def _check_status_code(host: Host) -> list[str]:
    if not host.headers or not host.headers.status_code:
        return []
    code = host.headers.status_code
    flags = []
    for flag, codes in _STATUS_CATEGORIES.items():
        if code in codes:
            flags.append(f"{flag}:{code}")
    return flags


def _check_version_disclosure(host: Host) -> list[str]:
    if not host.headers or not host.headers.present:
        return []
    flags = []
    for header, value in host.headers.present.items():
        if header in _VERSION_SKIP_HEADERS:
            continue
        if _VERSION_RE.search(value):
            flags.append(f"version_disclosed:{header}")
    return flags


_CDN_ASNS: frozenset[int] = frozenset({
    13335,   # Cloudflare
    209242,  # Cloudflare (secondary)
    54113,   # Fastly
    20940,   # Akamai
    16625,   # Akamai
    16509,   # Amazon / AWS
    14618,   # Amazon / AWS
    8075,    # Microsoft Azure
    15169,   # Google
    396982,  # Google Cloud
    36183,   # Akamai
    20446,   # Stackpath / Highwinds
    30148,   # Sucuri
    13238,   # Yandex
    132892,  # Cloudflare (APAC)
    394536,  # Fastly (secondary)
    46489,   # Twitch / Amazon
    16591,   # Google Fiber
    19551,   # Incapsula / Imperva
})


def _check_multiple_apex_owners(hosts: dict[str, Host]) -> dict[str, set[int]]:
    """Returns {apex: set_of_non_cdn_asns} for apexes with 2+ non-CDN ASNs."""
    apex_cdn: dict[str, set[int]] = defaultdict(set)
    apex_non_cdn: dict[str, set[int]] = defaultdict(set)
    for host in hosts.values():
        if not host.dns:
            continue
        for rip in host.dns.resolved_ips:
            if rip.asn and not rip.is_private:
                if rip.asn in _CDN_ASNS:
                    apex_cdn[host.apex].add(rip.asn)
                else:
                    apex_non_cdn[host.apex].add(rip.asn)

    flagged: dict[str, set[int]] = {}
    for apex, non_cdn_asns in apex_non_cdn.items():
        if len(non_cdn_asns) >= 2:
            flagged[apex] = non_cdn_asns
    return flagged


def _find_majority_asn(hosts: dict[str, Host]) -> dict[str, int]:
    """Returns {apex: most_common_non_cdn_asn} for outlier detection."""
    apex_asn_counts: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for host in hosts.values():
        if not host.dns:
            continue
        for rip in host.dns.resolved_ips:
            if rip.asn and not rip.is_private and rip.asn not in _CDN_ASNS:
                apex_asn_counts[host.apex][rip.asn] += 1

    majority: dict[str, int] = {}
    for apex, counts in apex_asn_counts.items():
        if counts:
            majority[apex] = max(counts, key=counts.get)
    return majority


async def _enrich_online_async(hosts: dict[str, Host]) -> None:
    """Batch ipinfo.io lookups for IPs missing ASN/country."""
    key = get_key("ipinfo")
    if not key:
        return

    ip_to_rips: dict[str, list[ResolvedIp]] = defaultdict(list)
    for host in hosts.values():
        if not host.dns:
            continue
        for rip in host.dns.resolved_ips:
            if not rip.is_private and not (rip.asn and rip.country):
                ip_to_rips[rip.ip].append(rip)

    if not ip_to_rips:
        return

    logger.info("Enriching %d unique IPs via ipinfo.io (concurrency=%d)", len(ip_to_rips), IPINFO_CONCURRENCY)
    sem = asyncio.Semaphore(IPINFO_CONCURRENCY)

    async with httpx.AsyncClient(timeout=5) as client:
        async def fetch(ip: str, rips: list[ResolvedIp]) -> None:
            async with sem:
                try:
                    resp = await client.get(
                        f"https://ipinfo.io/{ip}/json",
                        headers={"Authorization": f"Bearer {key}"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        provenance(module="analyze", action="ipinfo_enrich",
                                   ip=ip, country=data.get("country"),
                                   org=data.get("org"), city=data.get("city"))
                        for rip in rips:
                            if not rip.country:
                                rip.country = data.get("country")
                            if not rip.asn:
                                org = data.get("org", "")
                                if org.startswith("AS"):
                                    parts = org.split(" ", 1)
                                    try:
                                        rip.asn = int(parts[0][2:])
                                        rip.asn_org = parts[1] if len(parts) > 1 else None
                                    except ValueError:
                                        pass
                except Exception as e:
                    logger.debug("ipinfo.io lookup failed for %s: %s", ip, e)

        tasks = [asyncio.create_task(fetch(ip, rips)) for ip, rips in ip_to_rips.items()]
        await asyncio.gather(*tasks)


_SEVERITY_ORDER = ["critical", "high", "medium", "low"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}

_FLAG_SEVERITY: dict[str, str] = {
    "takeover": "critical",
    "ns_takeover_risk": "critical",
    "domain_expired": "critical",
    "stale_cname": "high",
    "mx_dangling": "high",
    "domain_expiring_soon": "high",
    "spf_permissive": "high",
    "private_ip_external": "high",
    "private_ip_leaked": "high",
    "geo_mismatch": "medium",
    "multiple_apex_owners": "medium",
    "unexpected_asn": "medium",
    "cert_expired": "critical",
    "cert_expiring_soon": "high",
    "cert_self_signed": "medium",
    "cors_wildcard_credentials": "medium",
    "cookies_missing_secure": "low",
    "cookies_missing_httponly": "low",
    "no_dnssec": "low",
    "version_disclosed": "low",
    "http_server_error": "low",
    "http_auth_required": "low",
    "http_not_found": "low",
    "http_redirect_permanent": "low",
    "wildcard_dns": "low",
    "sans_new_subdomains": "low",
    "lower_env_exposed": "medium",
    "wp_vulns": "high",
    "wp_outdated": "medium",
    "wp_theme_outdated": "low",
    "wp_plugins_outdated": "medium",
}

_DOMAIN_STATUS_SEVERITY: dict[str, str] = {
    "pendingdelete": "critical",
    "redemptionperiod": "critical",
    "serverhold": "high",
    "clienthold": "high",
    "pendingtransfer": "medium",
}


def _flag_severity(flag: str) -> str:
    if flag.startswith("domain_status:"):
        status = flag.split(":", 1)[1].lower().replace(" ", "")
        return _DOMAIN_STATUS_SEVERITY.get(status, "medium")
    prefix = flag.split(":")[0]
    return _FLAG_SEVERITY.get(prefix, "low")


def _max_severity(flags: list[str]) -> str | None:
    if not flags:
        return None
    best = len(_SEVERITY_ORDER)
    for flag in flags:
        rank = _SEVERITY_RANK.get(_flag_severity(flag), best)
        if rank < best:
            best = rank
    return _SEVERITY_ORDER[best] if best < len(_SEVERITY_ORDER) else "low"


_RDAP_EXPIRY_WARN_DAYS = 60
_RDAP_RISKY_STATUSES = frozenset({
    "pendingdelete",
    "redemptionperiod",
    "serverhold",
    "clienthold",
    "pendingtransfer",
})


def _check_rdap(host: Host) -> list[str]:
    if not host.rdap:
        return []
    flags = []
    if host.rdap.expires_at:
        try:
            exp_str = host.rdap.expires_at.replace("Z", "+00:00")
            exp = datetime.fromisoformat(exp_str)
            now = datetime.now(timezone.utc)
            days_left = (exp - now).days
            if days_left <= 0:
                flags.append("domain_expired")
            elif days_left <= _RDAP_EXPIRY_WARN_DAYS:
                flags.append(f"domain_expiring_soon:{days_left}d")
        except (ValueError, TypeError):
            pass
    for status in host.rdap.statuses:
        if status.lower().replace(" ", "") in _RDAP_RISKY_STATUSES:
            flags.append(f"domain_status:{status}")
    if host.rdap.dnssec is False:
        flags.append("no_dnssec")
    return flags


_CERT_EXPIRY_WARN_DAYS = 30


def _check_tls(host: Host) -> list[str]:
    if not host.tls:
        return []
    flags = []
    if host.tls.self_signed:
        flags.append("cert_self_signed")
    if host.tls.not_after:
        try:
            exp_str = host.tls.not_after.replace("Z", "+00:00")
            exp = datetime.fromisoformat(exp_str)
            now = datetime.now(timezone.utc)
            days_left = (exp - now).days
            if days_left <= 0:
                flags.append("cert_expired")
            elif days_left <= _CERT_EXPIRY_WARN_DAYS:
                flags.append(f"cert_expiring_soon:{days_left}d")
        except (ValueError, TypeError):
            pass
    return flags


def _check_cors(host: Host) -> list[str]:
    if not host.headers or not host.headers.present:
        return []
    origin = host.headers.present.get("access-control-allow-origin", "")
    creds = host.headers.present.get("access-control-allow-credentials", "").lower()
    if origin == "*" and creds == "true":
        return ["cors_wildcard_credentials"]
    return []


def _check_cookies(host: Host) -> list[str]:
    if not host.headers or not host.headers.cookies:
        return []
    flags = []
    has_insecure = any(not c.get("secure") for c in host.headers.cookies)
    has_no_httponly = any(not c.get("httponly") for c in host.headers.cookies)
    if has_insecure:
        flags.append("cookies_missing_secure")
    if has_no_httponly:
        flags.append("cookies_missing_httponly")
    return flags


_LOWER_ENV_FQDN_PATTERNS = re.compile(
    r"(?:^|[.\-])"
    r"(?:dev|develop|development|staging|stage|stg|qa|uat|test|testing|"
    r"sandbox|preprod|pre-prod|preproduction|internal|local|debug|"
    r"demo|beta|alpha|canary|nightly|experimental|lab|labs|poc)"
    r"(?:$|[.\-])",
    re.I,
)

_LOWER_ENV_TITLE_PATTERNS = re.compile(
    r"\b(?:staging|dev(?:elopment)?|qa|uat|test(?:ing)?|sandbox|preprod|"
    r"pre-prod|internal|demo|beta|alpha)\b",
    re.I,
)


def _check_wpscan(host: Host) -> list[str]:
    if not host.wpscan:
        return []
    flags = []
    if host.wpscan.vulnerabilities:
        flags.append(f"wp_vulns:{len(host.wpscan.vulnerabilities)}")
    if host.wpscan.wp_version_status == "insecure":
        flags.append("wp_outdated")
    if host.wpscan.theme_outdated:
        flags.append("wp_theme_outdated")
    outdated_plugins = [p.slug for p in host.wpscan.plugins if p.outdated]
    if outdated_plugins:
        flags.append(f"wp_plugins_outdated:{len(outdated_plugins)}")
    return flags


def _check_leaked_ips(host: Host) -> bool:
    return bool(host.headers and host.headers.leaked_ips)


def _check_lower_env(host: Host) -> bool:
    if _LOWER_ENV_FQDN_PATTERNS.search(host.fqdn):
        return True
    if host.headers and host.headers.page_title:
        if _LOWER_ENV_TITLE_PATTERNS.search(host.headers.page_title):
            return True
    return False


def _check_sans_new_subdomains(host: Host, all_fqdns: set[str]) -> set[str]:
    """Returns set of SAN FQDNs not present in the store."""
    new: set[str] = set()
    if not host.tls or not host.tls.sans:
        return new
    for san in host.tls.sans:
        san_lower = san.lower().lstrip("*.")
        if san_lower and san_lower not in all_fqdns:
            new.add(san_lower)
    return new


async def _run_network_prepasses(
    in_scope_hosts: dict[str, Host],
    fingerprints: list[TakeoverFingerprint],
    enrich_online: bool,
) -> tuple[dict[str, str], set[str], set[str], set[str]]:
    """Run all network-dependent checks concurrently.

    Returns (takeover_results, stale_fqdns, nxdomain_ns, nxdomain_mx).
    """
    # Collect takeover candidates
    takeover_results: dict[str, str] = {}
    takeover_candidates: list[tuple[Host, list[TakeoverFingerprint]]] = []
    for host in in_scope_hosts.values():
        nxdomain_service, needs_fetch = _match_takeover_cname(host, fingerprints)
        if nxdomain_service:
            takeover_results[host.fqdn] = nxdomain_service
        elif needs_fetch:
            takeover_candidates.append((host, needs_fetch))

    # Collect NS and MX hostnames that need resolution
    ns_candidates = _collect_ns_candidates(in_scope_hosts)
    mx_candidates = _collect_mx_candidates(in_scope_hosts)
    all_dns_hostnames = set(ns_candidates.keys()) | set(mx_candidates.keys())

    # Log what we're about to do
    counts = []
    if takeover_candidates:
        counts.append(f"{len(takeover_candidates)} takeover HTTP")
    counts.append(f"stale CNAME DNS")
    if all_dns_hostnames:
        counts.append(f"{len(all_dns_hostnames)} NS/MX DNS")
    if enrich_online:
        counts.append("ipinfo enrichment")
    logger.info("Running network checks: %s", ", ".join(counts))

    # Run ipinfo enrichment first (so geo checks have data)
    if enrich_online:
        await _enrich_online_async(in_scope_hosts)

    # Run stale CNAME, NS/MX DNS, and takeover HTTP concurrently
    stale_task = asyncio.create_task(_batch_stale_cname_checks(in_scope_hosts))
    dns_task = asyncio.create_task(_batch_dns_nxdomain_checks(all_dns_hostnames))

    takeover_task = None
    if takeover_candidates:
        takeover_task = asyncio.create_task(_check_takeovers_async(takeover_candidates))

    stale_fqdns = await stale_task
    nxdomain_hostnames = await dns_task

    if takeover_task:
        confirmed = await takeover_task
        takeover_results.update(confirmed)

    nxdomain_ns = nxdomain_hostnames & set(ns_candidates.keys())
    nxdomain_mx = nxdomain_hostnames & set(mx_candidates.keys())

    return takeover_results, stale_fqdns, nxdomain_ns, nxdomain_mx


def run_analyze(
    store_path: Path,
    expected_country: str | None = None,
    fingerprints_path: str | None = None,
    enrich_online: bool = False,
) -> set[str]:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return set()

    in_scope_hosts = {fqdn: h for fqdn, h in hosts.items() if not is_out_of_scope(h)}
    logger.info("Analyzing %d hosts (%d skipped as out-of-scope)", len(in_scope_hosts), len(hosts) - len(in_scope_hosts))

    fingerprints = _load_fingerprints(fingerprints_path)
    multi_apex = _check_multiple_apex_owners(in_scope_hosts)
    majority_asn = _find_majority_asn(in_scope_hosts)
    all_fqdns = set(hosts.keys())

    # --- Network pre-passes (all concurrent) ---
    takeover_results, stale_fqdns, nxdomain_ns, nxdomain_mx = asyncio.run(
        _run_network_prepasses(in_scope_hosts, fingerprints, enrich_online)
    )

    # --- Main analysis loop (pure in-memory) ---
    all_san_new_fqdns: set[str] = set()
    takeover_count = 0
    stale_count = 0
    geo_count = 0
    private_count = 0
    leaked_count = 0
    status_count = 0
    version_count = 0
    spf_count = 0
    ns_takeover_count = 0
    mx_dangling_count = 0
    rdap_count = 0
    tls_count = 0
    cors_count = 0
    cookie_count = 0
    lower_env_count = 0
    wpscan_count = 0

    for host in in_scope_hosts.values():
        if not host.analysis:
            host.analysis = AnalysisInfo()

        existing_flags = set(host.analysis.flags)

        # Stale CNAME
        if host.fqdn in stale_fqdns:
            existing_flags.add("stale_cname")
            stale_count += 1

        # Takeover
        takeover_service = takeover_results.get(host.fqdn)
        if takeover_service:
            existing_flags.add(f"takeover:{takeover_service}")
            host.analysis.takeover_candidate = True
            takeover_count += 1

        # Geo mismatch (skip if host has takeover/stale)
        if not takeover_service and "stale_cname" not in existing_flags:
            geo_flags = _check_geo_mismatch(host, expected_country)
            for gf in geo_flags:
                existing_flags.add(gf)
                geo_count += 1

        # Private IP on public record
        if _check_private_ip_external(host):
            existing_flags.add("private_ip_external")
            private_count += 1

        # Private IP leaked in HTTP headers/body
        if _check_leaked_ips(host):
            existing_flags.add("private_ip_leaked")
            leaked_count += 1

        # Multiple apex owners
        if host.apex in multi_apex:
            existing_flags.add("multiple_apex_owners")

        # Outlier ASN
        if host.dns and host.apex in majority_asn:
            maj = majority_asn[host.apex]
            for rip in host.dns.resolved_ips:
                if rip.asn and not rip.is_private and rip.asn not in _CDN_ASNS and rip.asn != maj:
                    existing_flags.add(f"unexpected_asn:{rip.asn}")
                    break

        # SPF misconfiguration
        if _check_spf_permissive(host):
            existing_flags.add("spf_permissive")
            spf_count += 1

        # NS delegation takeover risk (from pre-pass results)
        if host.dns and host.dns.ns:
            for ns in host.dns.ns:
                ns_lower = ns.lower().rstrip(".")
                if ns_lower in nxdomain_ns:
                    existing_flags.add(f"ns_takeover_risk:{ns_lower}")
                    host.analysis.takeover_candidate = True
                    ns_takeover_count += 1

        # Dangling MX (from pre-pass results)
        if host.dns and host.dns.mx:
            for mx_entry in host.dns.mx:
                parts = mx_entry.split()
                mx_host = parts[-1].rstrip(".").lower() if parts else ""
                if mx_host and mx_host in nxdomain_mx:
                    existing_flags.add(f"mx_dangling:{mx_host}")
                    mx_dangling_count += 1

        # RDAP-derived flags
        for rf in _check_rdap(host):
            existing_flags.add(rf)
            rdap_count += 1

        # TLS certificate flags
        for tf in _check_tls(host):
            existing_flags.add(tf)
            tls_count += 1

        # CORS misconfiguration
        for cf in _check_cors(host):
            existing_flags.add(cf)
            cors_count += 1

        # Cookie security
        for ck in _check_cookies(host):
            existing_flags.add(ck)
            cookie_count += 1

        # HTTP status code flags
        for sf in _check_status_code(host):
            existing_flags.add(sf)
            status_count += 1

        # Version/software disclosure in headers
        for vf in _check_version_disclosure(host):
            existing_flags.add(vf)
            version_count += 1

        # TLS SANs contain subdomains not in the store
        san_new = _check_sans_new_subdomains(host, all_fqdns)
        if san_new:
            existing_flags.add("sans_new_subdomains")
            all_san_new_fqdns.update(san_new)

        # Lower environment exposed publicly
        if _check_lower_env(host):
            existing_flags.add("lower_env_exposed")
            lower_env_count += 1

        # WPScan findings
        for wf in _check_wpscan(host):
            existing_flags.add(wf)
            wpscan_count += 1

        host.analysis.flags = sorted(existing_flags)
        host.analysis.severity = _max_severity(host.analysis.flags)

        if host.analysis.flags:
            provenance(module="analyze", action="analysis_result", fqdn=host.fqdn,
                       flags=host.analysis.flags, severity=host.analysis.severity,
                       takeover_candidate=host.analysis.takeover_candidate)

    save_store(store_path, hosts)

    flagged_total = sum(1 for h in in_scope_hosts.values() if h.analysis and h.analysis.flags)
    logger.info(
        "Analysis complete: %d takeover, %d stale CNAMEs, %d geo, %d private IPs, "
        "%d leaked IPs, %d SPF, %d NS takeover, %d MX dangling, %d RDAP, %d TLS, "
        "%d CORS, %d cookie, %d status, %d version, %d lower env, %d WPScan, %d total flagged",
        takeover_count, stale_count, geo_count, private_count,
        leaked_count, spf_count, ns_takeover_count, mx_dangling_count, rdap_count,
        tls_count, cors_count, cookie_count,
        status_count, version_count, lower_env_count, wpscan_count, flagged_total,
    )

    if all_san_new_fqdns:
        logger.info("SAN-discovered FQDNs not in store: %d", len(all_san_new_fqdns))

    return all_san_new_fqdns
