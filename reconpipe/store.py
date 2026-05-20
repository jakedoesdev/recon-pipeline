from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

logger = logging.getLogger(__name__)

from .models import (
    AnalysisInfo,
    DnsInfo,
    HeaderInfo,
    Host,
    LeakedIp,
    RdapContact,
    RdapInfo,
    ResolvedIp,
    ScopeInfo,
    TlsInfo,
    WpscanInfo,
    WpscanPlugin,
    _now_iso,
)


def _rebuild_host(raw: dict) -> Host:
    dns = None
    if raw.get("dns"):
        d = raw["dns"]
        resolved_ips = [ResolvedIp(**ip) for ip in (d.get("resolved_ips") or [])]
        dns = DnsInfo(
            a=d.get("a", []),
            aaaa=d.get("aaaa", []),
            txt=d.get("txt", []),
            mx=d.get("mx", []),
            ns=d.get("ns", []),
            cname_chain=d.get("cname_chain", []),
            resolved_ips=resolved_ips,
            nxdomain=d.get("nxdomain", False),
            resolution_error=d.get("resolution_error", False),
            resolver_used=d.get("resolver_used", ""),
            resolved_at=d.get("resolved_at", ""),
        )

    headers = None
    if raw.get("headers"):
        h = dict(raw["headers"])
        h["leaked_ips"] = [LeakedIp(**lip) for lip in (h.get("leaked_ips") or [])]
        headers = HeaderInfo(**h)

    scope = None
    if raw.get("scope"):
        scope = ScopeInfo(**raw["scope"])

    analysis = None
    if raw.get("analysis"):
        analysis = AnalysisInfo(**raw["analysis"])

    rdap = None
    if raw.get("rdap"):
        r = dict(raw["rdap"])
        r["contacts"] = [RdapContact(**c) for c in (r.get("contacts") or [])]
        rdap = RdapInfo(**r)

    tls = None
    if raw.get("tls"):
        tls = TlsInfo(**raw["tls"])

    wpscan = None
    if raw.get("wpscan"):
        w = dict(raw["wpscan"])
        w["plugins"] = [WpscanPlugin(**p) for p in (w.get("plugins") or [])]
        wpscan = WpscanInfo(**w)

    return Host(
        fqdn=raw["fqdn"],
        apex=raw["apex"],
        discovery_sources=raw.get("discovery_sources", []),
        first_seen=raw.get("first_seen", ""),
        last_updated=raw.get("last_updated", ""),
        dns=dns,
        headers=headers,
        scope=scope,
        analysis=analysis,
        rdap=rdap,
        tls=tls,
        wpscan=wpscan,
    )


def load_store(path: Path) -> dict[str, Host]:
    hosts: dict[str, Host] = {}
    if not path.exists():
        return hosts
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return hosts

    # Detect JSON array vs JSONL
    if content.startswith("["):
        records = json.loads(content)
        for raw in records:
            host = _rebuild_host(raw)
            hosts[host.fqdn] = host
    else:
        for lineno, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning("Skipping malformed JSONL at %s line %d: %s", path, lineno, e)
                continue
            try:
                host = _rebuild_host(raw)
            except (KeyError, TypeError) as e:
                logger.warning("Skipping unreadable record at %s line %d: %s", path, lineno, e)
                continue
            hosts[host.fqdn] = host
    return hosts


def save_store(path: Path, hosts: dict[str, Host]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for host in sorted(hosts.values(), key=lambda h: h.fqdn):
            f.write(json.dumps(asdict(host), separators=(",", ":")) + "\n")


def merge_host(existing: Host, incoming: Host) -> Host:
    existing.discovery_sources = list(
        dict.fromkeys(existing.discovery_sources + incoming.discovery_sources)
    )
    existing.last_updated = _now_iso()

    if incoming.dns is not None:
        existing.dns = incoming.dns
    if incoming.headers is not None:
        existing.headers = incoming.headers
    if incoming.scope is not None:
        existing.scope = incoming.scope
    if incoming.analysis is not None:
        existing.analysis = incoming.analysis
    if incoming.rdap is not None:
        existing.rdap = incoming.rdap
    if incoming.tls is not None:
        existing.tls = incoming.tls
    if incoming.wpscan is not None:
        existing.wpscan = incoming.wpscan

    return existing


def is_out_of_scope(host: Host) -> bool:
    return host.scope is not None and host.scope.status == "out"


def upsert_hosts(path: Path, new_hosts: list[Host]) -> dict[str, Host]:
    store = load_store(path)
    for host in new_hosts:
        if host.fqdn in store:
            store[host.fqdn] = merge_host(store[host.fqdn], host)
        else:
            store[host.fqdn] = host
    save_store(path, store)
    return store
