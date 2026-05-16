from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ResolvedIp:
    ip: str
    record_type: str
    is_private: bool
    asn: int | None = None
    asn_org: str | None = None
    country: str | None = None


@dataclass
class DnsInfo:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    resolved_ips: list[ResolvedIp] = field(default_factory=list)
    nxdomain: bool = False
    resolver_used: str = ""
    resolved_at: str = ""


@dataclass
class HeaderInfo:
    url_checked: str = ""
    status_code: int = 0
    present: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    source: str = "native"
    grade: str | None = None
    checked_at: str = ""


@dataclass
class ScopeInfo:
    status: str = "unmatched"
    matched_rule: str | None = None
    warning: str | None = None


@dataclass
class AnalysisInfo:
    flags: list[str] = field(default_factory=list)
    takeover_candidate: bool = False
    notes: str | None = None


@dataclass
class Host:
    fqdn: str
    apex: str
    discovery_sources: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: _now_iso())
    last_updated: str = field(default_factory=lambda: _now_iso())
    dns: DnsInfo | None = None
    headers: HeaderInfo | None = None
    scope: ScopeInfo | None = None
    analysis: AnalysisInfo | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
