from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from .config import get_key
from .log import provenance
from .models import WpscanInfo, WpscanPlugin, _now_iso
from .store import is_out_of_scope, load_store, save_store

logger = logging.getLogger(__name__)


class WpscanError(Exception):
    pass


def _find_wp_hosts(hosts: dict, refresh: bool) -> list:
    targets = []
    skipped = 0
    for host in hosts.values():
        if is_out_of_scope(host):
            continue
        if not host.headers or "WordPress" not in (host.headers.technologies or []):
            continue
        if not refresh and host.wpscan is not None:
            skipped += 1
            continue
        targets.append(host)
    if skipped:
        logger.info("Skipping %d hosts with existing WPScan data (use --refresh to re-scan)", skipped)
    return targets


def _build_cmd(url: str, api_token: str | None) -> list[str]:
    cmd = [
        "wpscan",
        "--url", url,
        "--format", "json",
        "--no-update",
        "--random-user-agent",
        "--disable-tls-checks",
    ]
    if api_token:
        cmd.extend(["--api-token", api_token])
    return cmd


def _parse_version(data: dict) -> tuple[str | None, str | None]:
    ver = data.get("version")
    if not ver:
        return None, None
    return ver.get("number"), ver.get("status")


def _parse_theme(data: dict) -> tuple[str | None, str | None, bool]:
    theme = data.get("main_theme")
    if not theme:
        return None, None, False
    slug = theme.get("slug") or theme.get("style_name")
    version = theme.get("version", {}).get("number") if isinstance(theme.get("version"), dict) else None
    outdated = theme.get("outdated", False)
    return slug, version, outdated


def _parse_plugins(data: dict) -> list[WpscanPlugin]:
    plugins_raw = data.get("plugins") or {}
    plugins = []
    for slug, info in plugins_raw.items():
        version = info.get("version", {}).get("number") if isinstance(info.get("version"), dict) else None
        outdated = info.get("outdated", False)
        vulns = []
        for v in info.get("vulnerabilities") or []:
            vulns.append({
                "title": v.get("title", ""),
                "type": v.get("vuln_type", ""),
                "cve": _extract_cve(v),
                "fixed_in": v.get("fixed_in"),
            })
        plugins.append(WpscanPlugin(
            slug=slug,
            version=version,
            outdated=outdated,
            vulnerabilities=vulns,
        ))
    return plugins


def _parse_vulns(data: dict) -> list[dict]:
    vulns = []
    for section_key in ("version", "main_theme"):
        section = data.get(section_key) or {}
        for v in section.get("vulnerabilities") or []:
            vulns.append({
                "title": v.get("title", ""),
                "type": v.get("vuln_type", ""),
                "affects": section_key,
                "cve": _extract_cve(v),
                "fixed_in": v.get("fixed_in"),
            })
    for slug, info in (data.get("plugins") or {}).items():
        for v in info.get("vulnerabilities") or []:
            vulns.append({
                "title": v.get("title", ""),
                "type": v.get("vuln_type", ""),
                "affects": f"plugin:{slug}",
                "cve": _extract_cve(v),
                "fixed_in": v.get("fixed_in"),
            })
    return vulns


def _extract_cve(vuln: dict) -> str | None:
    refs = vuln.get("references") or {}
    cves = refs.get("cve") or []
    return f"CVE-{cves[0]}" if cves else None


def _parse_interesting(data: dict) -> list[dict]:
    findings = []
    for item in data.get("interesting_findings") or []:
        findings.append({
            "url": item.get("url", ""),
            "type": item.get("type", ""),
            "description": (item.get("to_s") or "")[:300],
            "references": item.get("references", {}),
        })
    return findings


def _parse_wpscan_json(data: dict) -> WpscanInfo:
    wp_version, wp_version_status = _parse_version(data)
    theme, theme_version, theme_outdated = _parse_theme(data)
    plugins = _parse_plugins(data)
    vulns = _parse_vulns(data)
    interesting = _parse_interesting(data)

    return WpscanInfo(
        wp_version=wp_version,
        wp_version_status=wp_version_status,
        theme=theme,
        theme_version=theme_version,
        theme_outdated=theme_outdated,
        plugins=plugins,
        vulnerabilities=vulns,
        interesting_findings=interesting,
        scanned_at=_now_iso(),
    )


def _save_raw_output(fqdn: str, raw_json: str, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = fqdn.replace("*", "_").replace("/", "_")
    (output_dir / f"{safe_name}.json").write_text(raw_json, encoding="utf-8")


def run_wpscan(
    store_path: Path,
    refresh: bool = False,
    api_token: str | None = None,
) -> None:
    if not shutil.which("wpscan"):
        raise WpscanError("wpscan not found on PATH. Install: apt install wpscan (or gem install wpscan)")

    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    token = api_token or get_key("wpscan")
    if not token:
        logger.warning("No WPScan API token configured — vulnerability data will not be available. "
                       "Add wpscan key to keys.toml or pass --api-token")

    targets = _find_wp_hosts(hosts, refresh)
    logger.info("WPScan: %d WordPress hosts to scan", len(targets))
    if not targets:
        return

    output_dir = store_path.parent / "wpscan_out"
    scanned = 0
    vuln_total = 0

    for host in targets:
        url = host.headers.url_checked or f"https://{host.fqdn}"
        cmd = _build_cmd(url, token)
        logger.info("WPScan [%d/%d]: %s", scanned + 1, len(targets), host.fqdn)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError:
            raise WpscanError("wpscan not found on PATH")
        except subprocess.TimeoutExpired:
            logger.warning("WPScan timed out for %s (5 min), skipping", host.fqdn)
            provenance(module="wpscan", action="wpscan_timeout", fqdn=host.fqdn, url=url)
            continue

        raw_output = result.stdout
        _save_raw_output(host.fqdn, raw_output, output_dir)

        try:
            data = json.loads(raw_output)
        except (json.JSONDecodeError, ValueError):
            logger.warning("WPScan returned non-JSON output for %s (exit code %d)", host.fqdn, result.returncode)
            if result.stderr:
                logger.debug("WPScan stderr: %s", result.stderr[:500])
            provenance(module="wpscan", action="wpscan_failed", fqdn=host.fqdn, url=url,
                       exit_code=result.returncode, error=result.stderr[:200] if result.stderr else "non-json output")
            continue

        info = _parse_wpscan_json(data)
        host.wpscan = info
        hosts[host.fqdn] = host

        vuln_count = len(info.vulnerabilities)
        vuln_total += vuln_count

        provenance(
            module="wpscan", action="wpscan_complete", fqdn=host.fqdn, url=url,
            wp_version=info.wp_version, theme=info.theme,
            plugin_count=len(info.plugins), vuln_count=vuln_count,
            interesting_count=len(info.interesting_findings),
        )

        scanned += 1
        if scanned % 5 == 0:
            save_store(store_path, hosts)
            logger.info("Progress: %d/%d scanned", scanned, len(targets))

    save_store(store_path, hosts)
    logger.info("WPScan complete: %d/%d scanned, %d total vulnerabilities found, raw output in %s",
                scanned, len(targets), vuln_total, output_dir)
