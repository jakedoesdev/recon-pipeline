from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from .models import Host
from .store import is_out_of_scope, load_store, save_store

logger = logging.getLogger(__name__)

FLUSH_INTERVAL = 25


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
    ips: set[str],
    hosts: dict[str, Host],
    store_path: Path,
    resolvers: list[str],
    concurrency: int,
) -> tuple[dict[str, str], bool]:
    """Returns ({ip: ptr_hostname}, interrupted) for successful lookups."""
    interrupted = False

    def _handle_sigint(signum, frame):
        nonlocal interrupted
        interrupted = True
        logger.warning("Interrupt received — finishing in-flight lookups and saving progress")

    prev_handler = signal.signal(signal.SIGINT, _handle_sigint)

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.timeout = 5
    resolver.lifetime = 10

    sem = asyncio.Semaphore(concurrency)
    results: dict[str, str] = {}
    total = len(ips)

    async def lookup(ip: str) -> tuple[str, str | None]:
        async with sem:
            hostname = await _ptr_lookup(resolver, ip)
            return ip, hostname

    pending: set[asyncio.Task] = set()
    for ip in ips:
        if interrupted:
            break
        task = asyncio.create_task(lookup(ip))
        pending.add(task)

    checked = 0
    while pending:
        done, pending = await asyncio.wait(
            pending, return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            try:
                ip, hostname = task.result()
                if hostname:
                    results[ip] = hostname
            except Exception as e:
                logger.debug("PTR task failed: %s", e)
            checked += 1
            if checked % FLUSH_INTERVAL == 0:
                logger.info("Progress: %d/%d IPs checked", checked, total)
                _apply_ptr_results(hosts, results)
                save_store(store_path, hosts)

    signal.signal(signal.SIGINT, prev_handler)
    return results, interrupted


def _apply_ptr_results(hosts: dict[str, Host], ptr_map: dict[str, str]) -> None:
    for host in hosts.values():
        if not host.dns or host.dns.nxdomain:
            continue
        for rip in host.dns.resolved_ips:
            ptr = ptr_map.get(rip.ip)
            if ptr:
                rip.ptr = ptr


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

    ptr_map, interrupted = asyncio.run(_reverse_all(
        ips=unique_ips,
        hosts=hosts,
        store_path=store_path,
        resolvers=resolvers,
        concurrency=concurrency,
    ))

    _apply_ptr_results(hosts, ptr_map)
    save_store(store_path, hosts)

    if interrupted:
        logger.info("Reverse DNS interrupted — progress saved. %d/%d IPs have PTR records", len(ptr_map), len(unique_ips))
    else:
        logger.info("PTR results: %d/%d IPs have reverse DNS", len(ptr_map), len(unique_ips))
