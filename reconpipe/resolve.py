from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import signal
import string
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

from .models import DnsInfo, Host, ResolvedIp, _now_iso
from .store import is_out_of_scope, load_store, save_store

logger = logging.getLogger(__name__)

CNAME_DEPTH_LIMIT = 10
FLUSH_INTERVAL = 25


def _is_private(ip_str: str) -> bool:
    addr = ipaddress.ip_address(ip_str)
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _random_label() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


async def _resolve_record(
    resolver: dns.asyncresolver.Resolver,
    fqdn: str,
    rdtype: str,
) -> list[str]:
    try:
        answer = await resolver.resolve(fqdn, rdtype)
        return [rdata.to_text().rstrip(".") for rdata in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []
    except Exception as e:
        logger.debug("Resolve %s %s failed: %s", fqdn, rdtype, e)
        return []


async def _walk_cname_chain(
    resolver: dns.asyncresolver.Resolver,
    fqdn: str,
) -> list[str]:
    chain: list[str] = []
    current = fqdn
    for _ in range(CNAME_DEPTH_LIMIT):
        try:
            answer = await resolver.resolve(current, "CNAME")
            target = answer[0].to_text().rstrip(".")
            chain.append(target)
            current = target
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            break
        except Exception:
            break
    return chain


async def _check_nxdomain(
    resolver: dns.asyncresolver.Resolver,
    fqdn: str,
) -> bool:
    try:
        await resolver.resolve(fqdn, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return False
    except Exception:
        return False


async def _resolve_host(
    resolver: dns.asyncresolver.Resolver,
    host: Host,
    resolver_str: str,
    asn_lookup: object | None,
    country_lookup: object | None,
) -> Host:
    nxdomain = await _check_nxdomain(resolver, host.fqdn)

    if nxdomain:
        host.dns = DnsInfo(
            nxdomain=True,
            resolver_used=resolver_str,
            resolved_at=_now_iso(),
        )
        return host

    a_records = await _resolve_record(resolver, host.fqdn, "A")
    aaaa_records = await _resolve_record(resolver, host.fqdn, "AAAA")
    txt_records = await _resolve_record(resolver, host.fqdn, "TXT")
    mx_records = await _resolve_record(resolver, host.fqdn, "MX")
    ns_records = await _resolve_record(resolver, host.fqdn, "NS")
    cname_chain = await _walk_cname_chain(resolver, host.fqdn)

    # If there's a CNAME chain, also resolve the final target
    cname_a: list[str] = []
    if cname_chain:
        final_target = cname_chain[-1]
        cname_a = await _resolve_record(resolver, final_target, "A")

    resolved_ips: list[ResolvedIp] = []

    for ip in a_records:
        rip = ResolvedIp(ip=ip, record_type="A", is_private=_is_private(ip))
        _enrich_ip(rip, asn_lookup, country_lookup)
        resolved_ips.append(rip)

    for ip in aaaa_records:
        rip = ResolvedIp(ip=ip, record_type="AAAA", is_private=_is_private(ip))
        _enrich_ip(rip, asn_lookup, country_lookup)
        resolved_ips.append(rip)

    for ip in cname_a:
        if not any(r.ip == ip for r in resolved_ips):
            rip = ResolvedIp(ip=ip, record_type="CNAME->A", is_private=_is_private(ip))
            _enrich_ip(rip, asn_lookup, country_lookup)
            resolved_ips.append(rip)

    host.dns = DnsInfo(
        a=a_records,
        aaaa=aaaa_records,
        txt=txt_records,
        mx=mx_records,
        ns=ns_records,
        cname_chain=cname_chain,
        resolved_ips=resolved_ips,
        nxdomain=False,
        resolver_used=resolver_str,
        resolved_at=_now_iso(),
    )
    return host


def _enrich_ip(rip: ResolvedIp, asn_lookup, country_lookup) -> None:
    if not asn_lookup and not country_lookup:
        return
    try:
        addr = ipaddress.ip_address(rip.ip)
        if addr.is_private:
            return
        if asn_lookup:
            match = asn_lookup.get(rip.ip)
            if match:
                rip.asn = match.get("autonomous_system_number")
                rip.asn_org = match.get("autonomous_system_organization")
        if country_lookup:
            match = country_lookup.get(rip.ip)
            if match:
                country = match.get("country", {})
                rip.country = country.get("iso_code")
    except Exception as e:
        logger.debug("Enrichment failed for %s: %s", rip.ip, e)


async def _detect_wildcards(
    resolver: dns.asyncresolver.Resolver,
    apexes: set[str],
) -> dict[str, set[str]]:
    """Returns {apex: set_of_wildcard_ips} for apexes that are wildcarded."""
    wildcard_map: dict[str, set[str]] = {}

    for apex in apexes:
        test_ips: list[set[str]] = []
        for _ in range(3):
            label = _random_label()
            fqdn = f"{label}.{apex}"
            a_records = await _resolve_record(resolver, fqdn, "A")
            if a_records:
                test_ips.append(set(a_records))
            else:
                break

        if len(test_ips) == 3 and test_ips[0] == test_ips[1] == test_ips[2] and test_ips[0]:
            wildcard_map[apex] = test_ips[0]
            logger.info("Wildcard detected for %s -> %s", apex, test_ips[0])

    return wildcard_map


async def _resolve_all(
    hosts: dict[str, Host],
    store_path: Path,
    resolvers: list[str],
    concurrency: int,
    wildcard_detect: bool,
    asn_db_path: str | None,
    country_db_path: str | None,
) -> tuple[dict[str, Host], bool]:
    interrupted = False

    def _handle_sigint(signum, frame):
        nonlocal interrupted
        interrupted = True
        logger.warning("Interrupt received — finishing in-flight queries and saving progress")

    prev_handler = signal.signal(signal.SIGINT, _handle_sigint)

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.timeout = 5
    resolver.lifetime = 10

    resolver_str = ",".join(resolvers)

    # Load MaxMind DBs if configured
    asn_lookup = None
    country_lookup = None
    if asn_db_path:
        try:
            import maxminddb
            asn_lookup = maxminddb.open_database(asn_db_path)
            logger.info("Loaded ASN database: %s", asn_db_path)
        except Exception as e:
            logger.warning("Failed to load ASN DB: %s", e)
    if country_db_path:
        try:
            import maxminddb
            country_lookup = maxminddb.open_database(country_db_path)
            logger.info("Loaded country database: %s", country_db_path)
        except Exception as e:
            logger.warning("Failed to load country DB: %s", e)

    # Wildcard detection
    wildcard_map: dict[str, set[str]] = {}
    if wildcard_detect:
        apexes = {h.apex for h in hosts.values()}
        wildcard_map = await _detect_wildcards(resolver, apexes)

    # Resolve all hosts with concurrency limit (skip denied hosts)
    sem = asyncio.Semaphore(concurrency)
    in_scope_hosts = [h for h in hosts.values() if not is_out_of_scope(h)]
    total = len(in_scope_hosts)

    async def resolve_with_sem(host: Host) -> Host:
        async with sem:
            return await _resolve_host(resolver, host, resolver_str, asn_lookup, country_lookup)

    pending: set[asyncio.Task] = set()
    for host in in_scope_hosts:
        if interrupted:
            break
        task = asyncio.create_task(resolve_with_sem(host))
        pending.add(task)

    checked = 0
    while pending:
        done, pending = await asyncio.wait(
            pending, return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            try:
                host = task.result()
                # Flag wildcard matches
                if host.dns and not host.dns.nxdomain and host.apex in wildcard_map:
                    wildcard_ips = wildcard_map[host.apex]
                    host_ips = {r.ip for r in host.dns.resolved_ips}
                    if host_ips and host_ips.issubset(wildcard_ips):
                        if not host.analysis:
                            from .models import AnalysisInfo
                            host.analysis = AnalysisInfo()
                        if "wildcard_dns" not in host.analysis.flags:
                            host.analysis.flags.append("wildcard_dns")
                hosts[host.fqdn] = host
            except Exception as e:
                logger.warning("Resolution error: %s", e)
            checked += 1
            if checked % FLUSH_INTERVAL == 0:
                logger.info("Progress: %d/%d resolved", checked, total)
                save_store(store_path, hosts)

    signal.signal(signal.SIGINT, prev_handler)

    # Cleanup
    if asn_lookup:
        asn_lookup.close()
    if country_lookup:
        country_lookup.close()

    return hosts, interrupted


def run_resolve(
    store_path: Path,
    resolvers: list[str],
    concurrency: int = 50,
    wildcard_detect: bool = True,
    asn_db: str | None = None,
    country_db: str | None = None,
) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store to resolve")
        return

    in_scope_count = sum(1 for h in hosts.values() if not is_out_of_scope(h))
    skipped = len(hosts) - in_scope_count
    logger.info("Resolving %d hosts, %d skipped as out-of-scope (concurrency=%d, resolvers=%s)",
                in_scope_count, skipped, concurrency, resolvers)

    hosts, interrupted = asyncio.run(_resolve_all(
        hosts=hosts,
        store_path=store_path,
        resolvers=resolvers,
        concurrency=concurrency,
        wildcard_detect=wildcard_detect,
        asn_db_path=asn_db,
        country_db_path=country_db,
    ))

    save_store(store_path, hosts)

    # Summary stats
    resolved_count = sum(1 for h in hosts.values() if h.dns and not h.dns.nxdomain)
    nxdomain_count = sum(1 for h in hosts.values() if h.dns and h.dns.nxdomain)
    private_count = sum(
        1 for h in hosts.values()
        if h.dns and any(r.is_private for r in h.dns.resolved_ips)
    )
    wildcard_count = sum(
        1 for h in hosts.values()
        if h.analysis and "wildcard_dns" in h.analysis.flags
    )

    if interrupted:
        logger.info(
            "Resolution interrupted — progress saved. %d resolved, %d NXDOMAIN, %d with private IPs, %d wildcard-flagged",
            resolved_count, nxdomain_count, private_count, wildcard_count,
        )
    else:
        logger.info(
            "Resolution complete: %d resolved, %d NXDOMAIN, %d with private IPs, %d wildcard-flagged",
            resolved_count, nxdomain_count, private_count, wildcard_count,
        )
