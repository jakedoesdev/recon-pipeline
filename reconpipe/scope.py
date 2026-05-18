from __future__ import annotations

import logging
import re
from pathlib import Path

from .log import provenance
from .models import Host, ScopeInfo
from .store import load_store, save_store

logger = logging.getLogger(__name__)


def _load_patterns(path: str | None) -> list[str]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        logger.warning("Scope file not found: %s", path)
        return []
    return [line.strip() for line in p.read_text().splitlines() if line.strip() and not line.startswith("#")]


def _matches(fqdn: str, pattern: str) -> bool:
    if pattern.startswith("re:"):
        regex = pattern[3:]
        return bool(re.fullmatch(regex, fqdn))
    elif pattern.startswith("*."):
        suffix = pattern[1:]  # e.g. ".acme.com"
        return fqdn.endswith(suffix) or fqdn == pattern[2:]
    else:
        return fqdn == pattern


def _classify(fqdn: str, allow: list[str], deny: list[str]) -> ScopeInfo:
    for pattern in deny:
        if _matches(fqdn, pattern):
            return ScopeInfo(status="out", matched_rule=f"deny:{pattern}", warning=None)

    for pattern in allow:
        if _matches(fqdn, pattern):
            return ScopeInfo(status="in", matched_rule=f"allow:{pattern}", warning=None)

    return ScopeInfo(
        status="unmatched",
        matched_rule=None,
        warning="No allow/deny rule covers this host; defaulted unmatched. Review and update scope lists.",
    )


def _redirect_matches(host: Host, redirect_deny: list[str]) -> str | None:
    if not host.headers or not host.headers.redirect_chain:
        return None
    for url in host.headers.redirect_chain:
        for pattern in redirect_deny:
            if pattern.startswith("re:"):
                if re.search(pattern[3:], url):
                    return f"redirect-deny:re:{pattern[3:]}"
            elif pattern in url:
                return f"redirect-deny:{pattern}"
    return None


def run_scope(
    store_path: Path,
    allow_path: str | None,
    deny_path: str | None,
    redirect_deny_path: str | None = None,
) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    allow = _load_patterns(allow_path)
    deny = _load_patterns(deny_path)
    redirect_deny = _load_patterns(redirect_deny_path)

    if not allow and not deny:
        logger.warning("No allow or deny patterns provided — all hosts will be 'unmatched'")

    in_count = 0
    out_count = 0
    unmatched_count = 0
    redirect_deny_count = 0

    for host in hosts.values():
        host.scope = _classify(host.fqdn, allow, deny)

        if host.scope.status != "out" and redirect_deny:
            matched_rule = _redirect_matches(host, redirect_deny)
            if matched_rule:
                host.scope = ScopeInfo(status="out", matched_rule=matched_rule)
                redirect_deny_count += 1

        if host.scope.status == "in":
            in_count += 1
        elif host.scope.status == "out":
            out_count += 1
        else:
            unmatched_count += 1

    save_store(store_path, hosts)
    logger.info("Scope complete: %d in, %d out, %d unmatched", in_count, out_count, unmatched_count)
    if redirect_deny_count:
        logger.info("Redirect-deny matched %d hosts", redirect_deny_count)
    provenance(module="scope", action="scope_complete",
               total=len(hosts), in_scope=in_count, out_scope=out_count,
               unmatched=unmatched_count, redirect_denied=redirect_deny_count,
               allow_rules=len(allow), deny_rules=len(deny),
               redirect_deny_rules=len(redirect_deny))
