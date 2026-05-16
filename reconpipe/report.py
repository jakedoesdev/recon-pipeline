from __future__ import annotations

import sys
from pathlib import Path

import click

from .store import load_store


def report_subs(store_path: Path | str, scope: list[str], output: str | None) -> None:
    hosts = load_store(Path(store_path))
    lines: list[str] = []
    for host in sorted(hosts.values(), key=lambda h: h.fqdn):
        if _scope_matches(host, scope):
            lines.append(host.fqdn)

    _write_output("\n".join(lines), output)


def report_ips(store_path: Path | str, scope: list[str], output: str | None, include_private: bool = False) -> None:
    hosts = load_store(Path(store_path))
    ips: set[str] = set()
    for host in hosts.values():
        if not _scope_matches(host, scope):
            continue
        if not host.dns:
            continue
        for rip in host.dns.resolved_ips:
            if rip.is_private and not include_private:
                continue
            ips.add(rip.ip)

    _write_output("\n".join(sorted(ips)), output)


def report_subs_ips(store_path: Path | str, scope: list[str], output: str | None) -> None:
    hosts = load_store(Path(store_path))
    lines: list[str] = ["fqdn,ip,record_type"]
    for host in sorted(hosts.values(), key=lambda h: h.fqdn):
        if not _scope_matches(host, scope):
            continue
        if not host.dns:
            continue
        for rip in host.dns.resolved_ips:
            lines.append(f"{host.fqdn},{rip.ip},{rip.record_type}")

    _write_output("\n".join(lines), output)


def report_headers(store_path: Path | str, scope: list[str], output: str | None) -> None:
    hosts = load_store(Path(store_path))
    lines: list[str] = ["fqdn,status,grade,source,missing_headers,present_headers"]
    for host in sorted(hosts.values(), key=lambda h: h.fqdn):
        if not _scope_matches(host, scope):
            continue
        if not host.headers:
            continue
        missing = "|".join(host.headers.missing)
        present = "|".join(host.headers.present.keys())
        grade = host.headers.grade or ""
        lines.append(
            f"{host.fqdn},{host.headers.status_code},{grade},{host.headers.source},{missing},{present}"
        )

    _write_output("\n".join(lines), output)


def _scope_matches(host, scope: list[str]) -> bool:
    if "all" in scope:
        return True
    status = host.scope.status if host.scope else "unmatched"
    return status in scope


def _write_output(text: str, output: str | None) -> None:
    if text and not text.endswith("\n"):
        text += "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
