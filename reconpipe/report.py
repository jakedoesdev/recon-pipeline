from __future__ import annotations

import csv
import io
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .models import Host, ip_sort_key
from .store import load_store


def _has_public_ip(host: Host) -> bool:
    if not host.dns or not host.dns.resolved_ips:
        return False
    return any(not rip.is_private for rip in host.dns.resolved_ips)


def _resolves_only_private(host: Host) -> bool:
    if not host.dns or not host.dns.resolved_ips:
        return False
    return all(rip.is_private for rip in host.dns.resolved_ips)


def report_subs(store_path: Path | str, scope: list[str], output: str | None, **kwargs) -> None:
    hosts = load_store(Path(store_path))
    flagged_only = kwargs.get("flagged_only", False)
    lines: list[str] = []
    for host in sorted(hosts.values(), key=lambda h: h.fqdn):
        if not _scope_matches(host, scope):
            continue
        if flagged_only and not _has_flags(host):
            continue
        if _resolves_only_private(host):
            continue
        lines.append(host.fqdn)

    _write_output("\n".join(lines), output)


def report_ips(store_path: Path | str, scope: list[str], output: str | None, **kwargs) -> None:
    hosts = load_store(Path(store_path))
    include_private = kwargs.get("include_private", False)
    flagged_only = kwargs.get("flagged_only", False)
    ips: set[str] = set()
    for host in hosts.values():
        if not _scope_matches(host, scope):
            continue
        if flagged_only and not _has_flags(host):
            continue
        if not host.dns:
            continue
        for rip in host.dns.resolved_ips:
            if rip.is_private and not include_private:
                continue
            ips.add(rip.ip)

    _write_output("\n".join(sorted(ips, key=ip_sort_key)), output)


def report_subs_ips(store_path: Path | str, scope: list[str], output: str | None, **kwargs) -> None:
    hosts = load_store(Path(store_path))
    flagged_only = kwargs.get("flagged_only", False)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["fqdn", "ip", "record_type"])
    for host in sorted(hosts.values(), key=lambda h: h.fqdn):
        if not _scope_matches(host, scope):
            continue
        if flagged_only and not _has_flags(host):
            continue
        if not host.dns:
            continue
        for rip in host.dns.resolved_ips:
            if rip.is_private:
                continue
            writer.writerow([host.fqdn, rip.ip, rip.record_type])

    _write_output(buf.getvalue(), output)


def report_private(store_path: Path | str, scope: list[str], output: str | None, **kwargs) -> None:
    hosts = load_store(Path(store_path))
    flagged_only = kwargs.get("flagged_only", False)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["fqdn", "ip", "record_type"])
    for host in sorted(hosts.values(), key=lambda h: h.fqdn):
        if not _scope_matches(host, scope):
            continue
        if flagged_only and not _has_flags(host):
            continue
        if not host.dns:
            continue
        private_ips = [rip for rip in host.dns.resolved_ips if rip.is_private]
        if not private_ips:
            continue
        for rip in private_ips:
            writer.writerow([host.fqdn, rip.ip, rip.record_type])

    _write_output(buf.getvalue(), output)


def report_headers(store_path: Path | str, scope: list[str], output: str | None, **kwargs) -> None:
    hosts = load_store(Path(store_path))
    flagged_only = kwargs.get("flagged_only", False)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["fqdn", "status", "grade", "source", "missing_headers", "present_headers"])
    for host in sorted(hosts.values(), key=lambda h: h.fqdn):
        if not _scope_matches(host, scope):
            continue
        if flagged_only and not _has_flags(host):
            continue
        if not host.headers:
            continue
        missing = "|".join(host.headers.missing)
        present = "|".join(host.headers.present.keys())
        grade = host.headers.grade or ""
        writer.writerow([host.fqdn, host.headers.status_code, grade, host.headers.source, missing, present])

    _write_output(buf.getvalue(), output)


def report_combined(
    store_path: Path | str,
    scope: list[str],
    output: str | None,
    fmt: str = "json",
    flagged_only: bool = False,
) -> None:
    hosts = load_store(Path(store_path))

    # When multiple scope buckets requested with -o, write separate files
    if output and len(scope) > 1 and "all" not in scope:
        for bucket in scope:
            _write_combined_bucket(hosts, bucket, output, fmt, flagged_only)
        return

    # Single bucket or stdout
    filtered = _filter_hosts(hosts, scope, flagged_only)

    if fmt == "csv":
        _write_combined_csv(filtered, output)
    elif fmt == "json-array":
        records = [asdict(h) for h in filtered]
        _write_output(json.dumps(records, indent=2), output)
    else:
        # JSONL (default for combined)
        lines = [json.dumps(asdict(h), separators=(",", ":")) for h in filtered]
        _write_output("\n".join(lines), output)


def _write_combined_bucket(
    hosts: dict[str, Host],
    bucket: str,
    output: str,
    fmt: str,
    flagged_only: bool,
) -> None:
    p = Path(output)
    suffix = p.suffix or ".jsonl"
    stem = p.stem
    parent = p.parent
    bucket_path = str(parent / f"{stem}.{bucket}{suffix}")

    filtered = _filter_hosts(hosts, [bucket], flagged_only)
    if not filtered:
        return

    if fmt == "csv":
        _write_combined_csv(filtered, bucket_path)
    elif fmt == "json-array":
        records = [asdict(h) for h in filtered]
        _write_output(json.dumps(records, indent=2), bucket_path)
    else:
        lines = [json.dumps(asdict(h), separators=(",", ":")) for h in filtered]
        _write_output("\n".join(lines), bucket_path)


def _write_combined_csv(hosts: list[Host], output: str | None) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["fqdn", "apex", "discovery_sources", "scope_status", "a_records",
                      "cname_chain", "flags", "header_grade", "missing_headers"])
    for host in hosts:
        sources = "|".join(host.discovery_sources)
        scope_status = host.scope.status if host.scope else ""
        a_records = "|".join(host.dns.a) if host.dns else ""
        cname = "|".join(host.dns.cname_chain) if host.dns else ""
        flags = "|".join(host.analysis.flags) if host.analysis else ""
        grade = host.headers.grade or "" if host.headers else ""
        missing = "|".join(host.headers.missing) if host.headers else ""
        writer.writerow([host.fqdn, host.apex, sources, scope_status, a_records, cname, flags, grade, missing])

    _write_output(buf.getvalue(), output)


def _filter_hosts(hosts: dict[str, Host], scope: list[str], flagged_only: bool) -> list[Host]:
    result: list[Host] = []
    for host in sorted(hosts.values(), key=lambda h: h.fqdn):
        if not _scope_matches(host, scope):
            continue
        if flagged_only and not _has_flags(host):
            continue
        result.append(host)
    return result


def _has_flags(host: Host) -> bool:
    return bool(host.analysis and host.analysis.flags)


def _scope_matches(host: Host, scope: list[str]) -> bool:
    if "all" in scope:
        return True
    status = host.scope.status if host.scope else "unmatched"
    return status in scope


def _write_output(text: str, output: str | None) -> None:
    if text and not text.endswith("\n"):
        text += "\n"
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
