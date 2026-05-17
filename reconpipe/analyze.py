from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import dns.exception
import httpx

from .config import get_key
from .fingerprints import BUILTIN_FINGERPRINTS, TakeoverFingerprint
from .models import AnalysisInfo, Host, ResolvedIp
from .store import is_out_of_scope, load_store, save_store

logger = logging.getLogger(__name__)

TAKEOVER_FETCH_TIMEOUT = 10


def _load_fingerprints(path: str | None) -> list[TakeoverFingerprint]:
    # TODO: support custom fingerprints file
    return BUILTIN_FINGERPRINTS


def _is_domain_unregistered(fqdn: str) -> bool:
    """Check if a domain appears unregistered by querying SOA then NS."""
    import tldextract
    ext = tldextract.extract(fqdn)
    if not ext.domain or not ext.suffix:
        return False
    registrable = f"{ext.domain}.{ext.suffix}"
    for rdtype in ("SOA", "NS"):
        try:
            dns.resolver.resolve(registrable, rdtype)
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, Exception):
            continue
    return False


def _check_stale_cname(host: Host) -> bool:
    """CNAME chain exists but final target doesn't resolve or is unregistered."""
    if not host.dns or not host.dns.cname_chain:
        return False
    if not host.dns.resolved_ips and not host.dns.nxdomain:
        return True
    final_target = host.dns.cname_chain[-1]
    if _is_domain_unregistered(final_target):
        return True
    return False


def _check_takeover(host: Host, fingerprints: list[TakeoverFingerprint]) -> str | None:
    """Check if CNAME chain matches a takeover fingerprint and target appears unclaimed."""
    if not host.dns or not host.dns.cname_chain:
        return None

    chain_str = " ".join(host.dns.cname_chain).lower()

    for fp in fingerprints:
        matched_cname = any(pat.lower() in chain_str for pat in fp.cname_patterns)
        if not matched_cname:
            continue

        # If the fingerprint is vulnerable on NXDOMAIN and we have no IPs
        if fp.nxdomain_vulnerable and not host.dns.resolved_ips:
            return fp.service

        # Try to fetch and check body
        if _fetch_confirms_takeover(host.fqdn, fp):
            return fp.service

    return None


def _fetch_confirms_takeover(fqdn: str, fp: TakeoverFingerprint) -> bool:
    """HTTP fetch to confirm the takeover body pattern."""
    for scheme in ("https", "http"):
        try:
            with httpx.Client(timeout=TAKEOVER_FETCH_TIMEOUT, follow_redirects=True, verify=False) as client:
                resp = client.get(f"{scheme}://{fqdn}")
                body = resp.text[:5000]
                for pattern in fp.body_patterns:
                    if pattern.lower() in body.lower():
                        return True
        except Exception:
            continue
    return False


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


def _check_ns_takeover(host: Host) -> list[str]:
    if not host.dns or not host.dns.ns:
        return []
    flags = []
    for ns in host.dns.ns:
        ns_lower = ns.lower().rstrip(".")
        for pattern in _NS_TAKEOVER_PATTERNS:
            if ns_lower.endswith(pattern):
                try:
                    dns.resolver.resolve(ns_lower, "A")
                except dns.resolver.NXDOMAIN:
                    flags.append(f"ns_takeover_risk:{ns_lower}")
                except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                        dns.exception.Timeout, Exception):
                    pass
                break
    return flags


def _check_mx_dangling(host: Host) -> list[str]:
    if not host.dns or not host.dns.mx:
        return []
    flags = []
    for mx_entry in host.dns.mx:
        parts = mx_entry.split()
        mx_host = parts[-1].rstrip(".").lower() if parts else ""
        if not mx_host:
            continue
        try:
            dns.resolver.resolve(mx_host, "A")
        except dns.resolver.NXDOMAIN:
            flags.append(f"mx_dangling:{mx_host}")
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, Exception):
            pass
    return flags


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


def _enrich_online(host: Host) -> None:
    """Fall back to ipinfo.io for ASN/country when MaxMind DBs weren't available."""
    key = get_key("ipinfo")
    if not key:
        return

    for rip in host.dns.resolved_ips if host.dns else []:
        if rip.is_private or (rip.asn and rip.country):
            continue
        try:
            with httpx.Client(timeout=5) as client:
                headers = {"Authorization": f"Bearer {key}"}
                resp = client.get(f"https://ipinfo.io/{rip.ip}/json", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
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
            logger.debug("ipinfo.io lookup failed for %s: %s", rip.ip, e)


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


def run_analyze(
    store_path: Path,
    expected_country: str | None = None,
    fingerprints_path: str | None = None,
    enrich_online: bool = False,
) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    fingerprints = _load_fingerprints(fingerprints_path)
    multi_apex = _check_multiple_apex_owners(in_scope_hosts)
    majority_asn = _find_majority_asn(in_scope_hosts)

    in_scope_hosts = {fqdn: h for fqdn, h in hosts.items() if not is_out_of_scope(h)}
    logger.info("Analyzing %d hosts (%d skipped as out-of-scope)", len(in_scope_hosts), len(hosts) - len(in_scope_hosts))

    takeover_count = 0
    stale_count = 0
    geo_count = 0
    private_count = 0
    status_count = 0
    version_count = 0
    spf_count = 0
    ns_takeover_count = 0
    mx_dangling_count = 0
    rdap_count = 0
    tls_count = 0
    cors_count = 0
    cookie_count = 0

    for host in in_scope_hosts.values():
        if not host.analysis:
            host.analysis = AnalysisInfo()

        # Preserve existing flags (e.g. wildcard_dns from resolve)
        existing_flags = set(host.analysis.flags)

        # Online enrichment first (so geo check has data)
        if enrich_online and host.dns:
            _enrich_online(host)

        # Takeover and stale CNAME first (before geo, per design doc)
        if _check_stale_cname(host):
            existing_flags.add("stale_cname")
            stale_count += 1

        takeover_service = _check_takeover(host, fingerprints)
        if takeover_service:
            existing_flags.add(f"takeover:{takeover_service}")
            host.analysis.takeover_candidate = True
            takeover_count += 1

        # Geo mismatch (skip if host has takeover/stale — geo on third-party isn't meaningful)
        if not takeover_service and "stale_cname" not in existing_flags:
            geo_flags = _check_geo_mismatch(host, expected_country)
            for gf in geo_flags:
                existing_flags.add(gf)
                geo_count += 1

        # Private IP on public record
        if _check_private_ip_external(host):
            existing_flags.add("private_ip_external")
            private_count += 1

        # Multiple apex owners
        if host.apex in multi_apex:
            existing_flags.add("multiple_apex_owners")

        # Outlier ASN — host's non-CDN ASN differs from the apex majority
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

        # NS delegation takeover risk
        for nf in _check_ns_takeover(host):
            existing_flags.add(nf)
            host.analysis.takeover_candidate = True
            ns_takeover_count += 1

        # Dangling MX
        for mf in _check_mx_dangling(host):
            existing_flags.add(mf)
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

        host.analysis.flags = sorted(existing_flags)
        host.analysis.severity = _max_severity(host.analysis.flags)

    save_store(store_path, hosts)

    flagged_total = sum(1 for h in in_scope_hosts.values() if h.analysis and h.analysis.flags)
    logger.info(
        "Analysis complete: %d takeover, %d stale CNAMEs, %d geo, %d private IPs, "
        "%d SPF, %d NS takeover, %d MX dangling, %d RDAP, %d TLS, %d CORS, "
        "%d cookie, %d status, %d version, %d total flagged",
        takeover_count, stale_count, geo_count, private_count,
        spf_count, ns_takeover_count, mx_dangling_count, rdap_count,
        tls_count, cors_count, cookie_count,
        status_count, version_count, flagged_total,
    )
