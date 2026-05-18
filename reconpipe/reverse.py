from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from .models import DnsInfo, Host, ResolvedIp, _now_iso
from .store import is_out_of_scope, load_store, save_store

logger = logging.getLogger(__name__)


async def _ptr_lookup(
    resolver: dns.asyncresolver.Resolver,
    ip: str,
) -> str | None:
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = await resolver.resolve(rev_name, "PTR")
        for rdata in answer:
            return rdata.to_text().rstrip(".")
        return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception as e:
        logger.debug("PTR lookup failed for %s: %s", ip, e)
        return None


async def _reverse_all(
    ips: dict[str, str],
    resolvers: list[str],
    concurrency: int,
) -> dict[str, str]:
    """Returns {ip: ptr_hostname} for successful lookups."""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.timeout = 5
    resolver.lifetime = 10

    sem = asyncio.Semaphore(concurrency)
    results: dict[str, str] = {}

    async def lookup(ip: str) -> tuple[str, str | None]:
        async with sem:
            hostname = await _ptr_lookup(resolver, ip)
            return ip, hostname

    tasks = [lookup(ip) for ip in ips]
    for coro in asyncio.as_completed(tasks):
        ip, hostname = await coro
        if hostname:
            results[ip] = hostname

    return results


def run_reverse(
    store_path: Path,
    resolvers: list[str],
    concurrency: int = 50,
    refresh: bool = False,
) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    unique_ips: set[str] = set()
    already_have: set[str] = set()
    for host in hosts.values():
        if is_out_of_scope(host):
            continue
        if not host.dns or host.dns.nxdomain:
            continue
        for rip in host.dns.resolved_ips:
            if not rip.is_private:
                if not refresh and rip.ptr is not None:
                    already_have.add(rip.ip)
                else:
                    unique_ips.add(rip.ip)

    unique_ips -= already_have

    if already_have:
        logger.info("Skipping %d IPs with existing PTR data (use --refresh to re-check)", len(already_have))

    if not unique_ips:
        logger.warning("No public IPs to reverse-resolve")
        return

    logger.info("Reverse-resolving %d unique public IPs (concurrency=%d)", len(unique_ips), concurrency)

    ptr_map = asyncio.run(_reverse_all(
        ips=unique_ips,
        resolvers=resolvers,
        concurrency=concurrency,
    ))

    logger.info("PTR results: %d/%d IPs have reverse DNS", len(ptr_map), len(unique_ips))

    # Annotate existing hosts with PTR data
    for host in hosts.values():
        if not host.dns or host.dns.nxdomain:
            continue
        for rip in host.dns.resolved_ips:
            ptr = ptr_map.get(rip.ip)
            if ptr:
                rip.ptr = ptr

    save_store(store_path, hosts)
