from __future__ import annotations

import logging
from pathlib import Path

import httpx

from .models import RdapInfo, _now_iso
from .store import load_store, save_store

logger = logging.getLogger(__name__)

RDAP_BOOTSTRAP = "https://rdap.org/domain/"
RDAP_TIMEOUT = 15


def _parse_events(events: list[dict]) -> tuple[str | None, str | None]:
    registered = None
    expires = None
    for ev in events:
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")
        if action == "registration" and date:
            registered = date
        elif action == "expiration" and date:
            expires = date
    return registered, expires


def _parse_nameservers(ns_list: list[dict]) -> list[str]:
    servers = []
    for ns in ns_list:
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            servers.append(name.lower().rstrip("."))
    return servers


def _has_dnssec(raw: dict) -> bool | None:
    sec_dns = raw.get("secureDNS")
    if sec_dns is None:
        return None
    return bool(sec_dns.get("delegationSigned", False))


def _fetch_rdap(apex: str) -> RdapInfo | None:
    url = f"{RDAP_BOOTSTRAP}{apex}"
    try:
        with httpx.Client(timeout=RDAP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                logger.debug("RDAP %d for %s", resp.status_code, apex)
                return None

            data = resp.json()

            entities = data.get("entities", [])
            registrar = None
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcards = ent.get("vcardArray", [None, []])
                    for item in (vcards[1] if len(vcards) > 1 else []):
                        if item[0] == "fn":
                            registrar = item[3]
                            break
                    if not registrar:
                        registrar = ent.get("handle")
                    break

            registered, expires = _parse_events(data.get("events", []))
            nameservers = _parse_nameservers(data.get("nameservers", []))
            statuses = data.get("status", [])
            dnssec = _has_dnssec(data)

            return RdapInfo(
                registrar=registrar,
                registered_at=registered,
                expires_at=expires,
                statuses=statuses,
                nameservers=nameservers,
                dnssec=dnssec,
                queried_at=_now_iso(),
            )

    except Exception as e:
        logger.debug("RDAP lookup failed for %s: %s", apex, e)
        return None


def run_rdap(store_path: Path) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    apexes: set[str] = {h.apex for h in hosts.values()}
    logger.info("Querying RDAP for %d apex domains", len(apexes))

    rdap_cache: dict[str, RdapInfo | None] = {}
    success = 0

    for apex in sorted(apexes):
        info = _fetch_rdap(apex)
        rdap_cache[apex] = info
        if info:
            success += 1

    for host in hosts.values():
        info = rdap_cache.get(host.apex)
        if info:
            host.rdap = info

    save_store(store_path, hosts)
    logger.info("RDAP complete: %d/%d apex domains resolved", success, len(apexes))
