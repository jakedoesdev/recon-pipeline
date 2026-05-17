from __future__ import annotations

import logging
import socket
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from .models import TlsInfo, _now_iso
from .store import load_store, save_store

logger = logging.getLogger(__name__)

TLS_TIMEOUT = 10


def _get_cert_info(fqdn: str, port: int = 443) -> TlsInfo | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((fqdn, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=fqdn) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return None

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

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("TLS connection failed for %s: %s", fqdn, e)
        return None
    except Exception as e:
        logger.debug("TLS cert parsing failed for %s: %s", fqdn, e)
        return None


def run_tls(store_path: Path, port: int = 443) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    targets = [
        h for h in hosts.values()
        if h.dns and not h.dns.nxdomain and h.dns.resolved_ips
    ]

    logger.info("Checking TLS certificates on %d hosts", len(targets))

    success = 0
    for i, host in enumerate(targets, 1):
        info = _get_cert_info(host.fqdn, port)
        if info:
            host.tls = info
            success += 1
        if i % 25 == 0:
            logger.info("Progress: %d/%d checked", i, len(targets))

    save_store(store_path, hosts)
    logger.info("TLS complete: %d/%d hosts got certificates", success, len(targets))
