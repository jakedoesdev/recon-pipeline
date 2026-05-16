from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

from .models import Host
from .store import load_store


TRACKED_FIELDS = [
    "dns.resolved_ips",
    "dns.cname_chain",
    "headers.missing",
    "headers.grade",
    "scope.status",
    "analysis.flags",
    "discovery_sources",
]


def _extract_field(host: Host, field: str):
    parts = field.split(".")
    obj = host
    for part in parts:
        if obj is None:
            return None
        obj = getattr(obj, part, None)
    if isinstance(obj, list):
        return sorted(str(x) if not isinstance(x, str) else x for x in obj)
    return obj


def _resolve_ip_key(rip) -> str:
    return f"{rip.ip}({rip.record_type})"


def _resolved_ips_repr(host: Host) -> list[str] | None:
    if not host.dns or not host.dns.resolved_ips:
        return None
    return sorted(_resolve_ip_key(rip) for rip in host.dns.resolved_ips)


def _get_comparable(host: Host, field: str):
    if field == "dns.resolved_ips":
        return _resolved_ips_repr(host)
    return _extract_field(host, field)


def compute_diff(
    old_path: Path,
    new_path: Path,
    scope_filter: list[str],
) -> dict:
    old_hosts = load_store(old_path)
    new_hosts = load_store(new_path)

    old_fqdns = set(old_hosts.keys())
    new_fqdns = set(new_hosts.keys())

    added_fqdns = new_fqdns - old_fqdns
    removed_fqdns = old_fqdns - new_fqdns
    common_fqdns = old_fqdns & new_fqdns

    def in_scope(host: Host) -> bool:
        if "all" in scope_filter:
            return True
        status = host.scope.status if host.scope else "unmatched"
        return status in scope_filter

    added = [new_hosts[f] for f in sorted(added_fqdns) if in_scope(new_hosts[f])]
    removed = [old_hosts[f] for f in sorted(removed_fqdns) if in_scope(old_hosts[f])]

    changed: list[dict] = []
    for fqdn in sorted(common_fqdns):
        old_h = old_hosts[fqdn]
        new_h = new_hosts[fqdn]
        if not in_scope(new_h) and not in_scope(old_h):
            continue

        diffs: dict[str, dict] = {}
        for field in TRACKED_FIELDS:
            old_val = _get_comparable(old_h, field)
            new_val = _get_comparable(new_h, field)
            if old_val != new_val:
                diffs[field] = {"old": old_val, "new": new_val}

        if diffs:
            changed.append({"fqdn": fqdn, "changes": diffs})

    return {"added": added, "removed": removed, "changed": changed}


def format_text(result: dict) -> str:
    lines: list[str] = []

    if result["added"]:
        lines.append(f"=== ADDED ({len(result['added'])}) ===")
        for host in result["added"]:
            lines.append(f"  + {host.fqdn}")

    if result["removed"]:
        lines.append(f"=== REMOVED ({len(result['removed'])}) ===")
        for host in result["removed"]:
            lines.append(f"  - {host.fqdn}")

    if result["changed"]:
        lines.append(f"=== CHANGED ({len(result['changed'])}) ===")
        for entry in result["changed"]:
            lines.append(f"  ~ {entry['fqdn']}")
            for field, vals in entry["changes"].items():
                old_repr = vals["old"] if vals["old"] is not None else "(none)"
                new_repr = vals["new"] if vals["new"] is not None else "(none)"
                lines.append(f"      {field}: {old_repr} → {new_repr}")

    if not lines:
        lines.append("No differences found.")

    return "\n".join(lines)


def format_json(result: dict) -> str:
    out = {
        "added": [h.fqdn for h in result["added"]],
        "removed": [h.fqdn for h in result["removed"]],
        "changed": result["changed"],
    }
    return json.dumps(out, indent=2)


def format_csv(result: dict) -> str:
    lines: list[str] = ["status,fqdn,field,old_value,new_value"]
    for host in result["added"]:
        lines.append(f"added,{host.fqdn},,,")
    for host in result["removed"]:
        lines.append(f"removed,{host.fqdn},,,")
    for entry in result["changed"]:
        for field, vals in entry["changes"].items():
            old_str = _csv_safe(vals["old"])
            new_str = _csv_safe(vals["new"])
            lines.append(f"changed,{entry['fqdn']},{field},{old_str},{new_str}")
    return "\n".join(lines)


def _csv_safe(val) -> str:
    if val is None:
        return ""
    s = str(val)
    if "," in s or '"' in s or "\n" in s:
        return '"' + s.replace('"', '""') + '"'
    return s


def run_diff(
    old_path: str,
    new_path: str,
    scope: str,
    output: str | None,
    fmt: str,
) -> None:
    scope_list = [s.strip() for s in scope.split(",")]
    result = compute_diff(Path(old_path), Path(new_path), scope_list)

    if fmt == "json":
        text = format_json(result)
    elif fmt == "csv":
        text = format_csv(result)
    else:
        text = format_text(result)

    if not text.endswith("\n"):
        text += "\n"

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
