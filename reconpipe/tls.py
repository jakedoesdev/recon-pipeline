from __future__ import annotations

import asyncio
import collections
import logging
import signal
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from .models import Host, TlsInfo, _now_iso
from .store import is_out_of_scope, load_store, save_store

logger = logging.getLogger(__name__)

TLS_TIMEOUT = 10
FLUSH_INTERVAL = 25
PER_IP_LIMIT = 5


def _parse_cert(der: bytes) -> TlsInfo | None:
    cert = x509.load_der_x509_certificate(der)

    subject_cn = None
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        subject_cn = attr.value
        break

    issuer_cn = None
    for attr in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME):
        issuer_cn = attr.value
        break

    issuer_org = None
    for attr in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME):
        issuer_org = attr.value
        break

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    self_signed = cert.issuer == cert.subject

    return TlsInfo(
        subject=subject_cn,
        issuer=issuer_cn,
        issuer_org=issuer_org,
        not_before=cert.not_valid_before_utc.isoformat(timespec="seconds"),
        not_after=cert.not_valid_after_utc.isoformat(timespec="seconds"),
        serial=format(cert.serial_number, "x"),
        sans=sans,
        self_signed=self_signed,
        queried_at=_now_iso(),
    )


async def _get_cert_info(fqdn: str, port: int) -> TlsInfo | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(fqdn, port, ssl=ctx, server_hostname=fqdn),
            timeout=TLS_TIMEOUT,
        )

        ssl_obj = writer.get_extra_info("ssl_object")
        if not ssl_obj:
            writer.close()
            return None

        der = ssl_obj.getpeercert(binary_form=True)
        writer.close()
        await writer.wait_closed()

        if not der:
            return None

        return _parse_cert(der)

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        logger.debug("TLS connection failed for %s: %s", fqdn, e)
        return None
    except Exception as e:
        logger.debug("TLS cert parsing failed for %s: %s", fqdn, e)
        return None


def _host_primary_ip(host: Host) -> str:
    if host.dns and host.dns.resolved_ips:
        return host.dns.resolved_ips[0].ip
    return host.fqdn


async def _check_all(
    hosts: dict[str, Host],
    targets: list[Host],
    store_path: Path,
    port: int,
    concurrency: int,
) -> tuple[int, int, bool]:
    interrupted = False

    def _handle_sigint(signum, frame):
        nonlocal interrupted
        interrupted = True
        logger.warning("Interrupt received — finishing in-flight connections and saving progress")

    prev_handler = signal.signal(signal.SIGINT, _handle_sigint)

    global_sem = asyncio.Semaphore(concurrency)
    ip_sems: dict[str, asyncio.Semaphore] = collections.defaultdict(
        lambda: asyncio.Semaphore(PER_IP_LIMIT)
    )

    checked = 0
    success = 0

    async def process(host: Host) -> tuple[Host, TlsInfo | None]:
        ip = _host_primary_ip(host)
        async with global_sem, ip_sems[ip]:
            info = await _get_cert_info(host.fqdn, port)
            return host, info

    pending: set[asyncio.Task] = set()

    for host in targets:
        if interrupted:
            break
        task = asyncio.create_task(process(host))
        pending.add(task)

    while pending:
        done, pending = await asyncio.wait(
            pending, return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            try:
                host, info = task.result()
                if info:
                    host.tls = info
                    success += 1
                hosts[host.fqdn] = host
            except Exception as e:
                logger.debug("Task failed: %s", e)
            checked += 1
            if checked % FLUSH_INTERVAL == 0:
                logger.info("Progress: %d/%d checked", checked, len(targets))
                save_store(store_path, hosts)

    signal.signal(signal.SIGINT, prev_handler)
    return checked, success, interrupted


def run_tls(store_path: Path, port: int = 443, refresh: bool = False, concurrency: int = 30) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    eligible = [
        h for h in hosts.values()
        if not is_out_of_scope(h) and h.dns and not h.dns.nxdomain and h.dns.resolved_ips
    ]

    if refresh:
        targets = eligible
    else:
        targets = [h for h in eligible if h.tls is None]
        skipped = len(eligible) - len(targets)
        if skipped:
            logger.info("Skipping %d hosts with existing TLS data (use --refresh to re-check)", skipped)

    logger.info("Checking TLS certificates on %d hosts (concurrency=%d, per-IP limit=%d)",
                len(targets), concurrency, PER_IP_LIMIT)

    if not targets:
        return

    checked, success, interrupted = asyncio.run(_check_all(
        hosts=hosts,
        targets=targets,
        store_path=store_path,
        port=port,
        concurrency=concurrency,
    ))

    save_store(store_path, hosts)

    if interrupted:
        logger.info("TLS interrupted: %d/%d hosts checked (%d certs), progress saved", checked, len(targets), success)
    else:
        logger.info("TLS complete: %d/%d hosts got certificates", success, len(targets))
