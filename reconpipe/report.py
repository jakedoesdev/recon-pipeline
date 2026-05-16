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

    text = "\n".join(lines)
    if text:
        text += "\n"

    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _scope_matches(host, scope: list[str]) -> bool:
    if "all" in scope:
        return True
    status = host.scope.status if host.scope else "unmatched"
    return status in scope
