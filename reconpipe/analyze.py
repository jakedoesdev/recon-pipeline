from __future__ import annotations

import logging
import re
from collections import defaultdict
from pathlib import Path

import dns.resolver
import dns.exception
import httpx

from .config import get_key
from .fingerprints import BUILTIN_FINGERPRINTS, TakeoverFingerprint
from .models import AnalysisInfo, Host, ResolvedIp
from .store import load_store, save_store

logger = logging.getLogger(__name__)

TAKEOVER_FETCH_TIMEOUT = 10


def _load_fingerprints(path: str | None) -> list[TakeoverFingerprint]:
    # TODO: support custom fingerprints file
    return BUILTIN_FINGERPRINTS


def _check_stale_cname(host: Host) -> bool:
    """CNAME chain exists but final target is NXDOMAIN (detected during resolve as nxdomain=False but no IPs)."""
    if not host.dns or not host.dns.cname_chain:
        return False
    # If the host has a CNAME chain but resolved to nothing, it's stale
    if not host.dns.resolved_ips and not host.dns.nxdomain:
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


def _check_multiple_apex_owners(hosts: dict[str, Host]) -> set[str]:
    """Flag hosts under an apex that resolves to wildly different ASNs."""
    apex_asns: dict[str, set[int]] = defaultdict(set)
    for host in hosts.values():
        if not host.dns:
            continue
        for rip in host.dns.resolved_ips:
            if rip.asn and not rip.is_private:
                apex_asns[host.apex].add(rip.asn)

    flagged_apexes: set[str] = set()
    for apex, asns in apex_asns.items():
        if len(asns) >= 3:
            flagged_apexes.add(apex)
    return flagged_apexes


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
    multi_apex = _check_multiple_apex_owners(hosts)

    logger.info("Analyzing %d hosts", len(hosts))

    takeover_count = 0
    stale_count = 0
    geo_count = 0
    private_count = 0
    status_count = 0
    version_count = 0
    spf_count = 0
    ns_takeover_count = 0
    mx_dangling_count = 0

    for host in hosts.values():
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

        # HTTP status code flags
        for sf in _check_status_code(host):
            existing_flags.add(sf)
            status_count += 1

        # Version/software disclosure in headers
        for vf in _check_version_disclosure(host):
            existing_flags.add(vf)
            version_count += 1

        host.analysis.flags = sorted(existing_flags)

    save_store(store_path, hosts)

    flagged_total = sum(1 for h in hosts.values() if h.analysis and h.analysis.flags)
    logger.info(
        "Analysis complete: %d takeover candidates, %d stale CNAMEs, %d geo mismatches, "
        "%d private IPs, %d SPF permissive, %d NS takeover risks, %d dangling MX, "
        "%d status flags, %d version disclosures, %d total hosts flagged",
        takeover_count, stale_count, geo_count, private_count,
        spf_count, ns_takeover_count, mx_dangling_count,
        status_count, version_count, flagged_total,
    )
