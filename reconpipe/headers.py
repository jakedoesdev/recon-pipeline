from __future__ import annotations

import logging
import time
from pathlib import Path

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .models import HeaderInfo, Host, _now_iso
from .store import load_store, save_store

logger = logging.getLogger(__name__)

DEFAULT_EXPECTED = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

BONUS_HEADERS = ["Server", "X-Powered-By"]

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

SECURITYHEADERS_URL = "https://securityheaders.com/"
SECURITYHEADERS_RATE_LIMIT = 1.0  # seconds between requests


def _load_expected(path: str | None) -> list[str]:
    if not path:
        return DEFAULT_EXPECTED
    p = Path(path)
    if not p.exists():
        logger.warning("Expected headers file not found: %s, using defaults", path)
        return DEFAULT_EXPECTED
    return [line.strip() for line in p.read_text().splitlines() if line.strip()]


def _native_check(
    fqdn: str,
    scheme: str,
    expected: list[str],
    timeout: int,
    user_agent: str,
) -> HeaderInfo | None:
    url = f"{scheme}://{fqdn}"
    headers_dict: dict[str, str] = {}

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            # Try HEAD first
            try:
                resp = client.head(url, headers={"User-Agent": user_agent})
            except httpx.HTTPError:
                resp = None

            # Fall back to GET if HEAD fails or returns unusual status
            if resp is None or resp.status_code in (405, 501):
                resp = client.get(url, headers={"User-Agent": user_agent})

            for key in expected + BONUS_HEADERS:
                val = resp.headers.get(key)
                if val:
                    headers_dict[key.lower()] = val[:200]

            present = {k: v for k, v in headers_dict.items()}
            missing = [h for h in expected if h.lower() not in headers_dict]

            return HeaderInfo(
                url_checked=str(resp.url),
                status_code=resp.status_code,
                present=present,
                missing=missing,
                source="native",
                grade=None,
                checked_at=_now_iso(),
            )

    except httpx.TimeoutException:
        logger.debug("Timeout connecting to %s", url)
        return None
    except httpx.ConnectError:
        logger.debug("Connection failed to %s", url)
        return None
    except Exception as e:
        logger.debug("Native check failed for %s: %s", url, e)
        return None


@retry(
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=15),
    reraise=True,
)
def _securityheaders_fetch(url: str, timeout: int) -> tuple[str | None, dict]:
    """Query securityheaders.com for a grade. Returns (grade, raw_headers)."""
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(
            SECURITYHEADERS_URL,
            params={"q": url, "hide": "on", "followRedirects": "on"},
        )
        resp.raise_for_status()
        grade = resp.headers.get("X-Score") or resp.headers.get("x-score")
        return grade, dict(resp.headers)


def _securityheaders_check(
    fqdn: str,
    scheme: str,
    expected: list[str],
    timeout: int,
) -> HeaderInfo | None:
    url = f"{scheme}://{fqdn}"
    try:
        grade, _ = _securityheaders_fetch(url, timeout)
        return HeaderInfo(
            url_checked=url,
            status_code=0,
            present={},
            missing=[],
            source="securityheaders",
            grade=grade,
            checked_at=_now_iso(),
        )
    except Exception as e:
        logger.debug("securityheaders.com failed for %s: %s", url, e)
        return None


def _check_host(
    host: Host,
    scheme: str,
    source: str,
    expected: list[str],
    timeout: int,
    user_agent: str,
) -> Host:
    schemes = [scheme] if scheme != "both" else ["https", "http"]

    result: HeaderInfo | None = None

    for s in schemes:
        if source == "native":
            result = _native_check(host.fqdn, s, expected, timeout, user_agent)
        elif source == "securityheaders":
            result = _securityheaders_check(host.fqdn, s, expected, timeout)
            if not result:
                # Fall back to native on securityheaders failure
                result = _native_check(host.fqdn, s, expected, timeout, user_agent)
                if result:
                    result.source = "securityheaders_then_native"
        elif source == "both":
            # Native first for raw values, then securityheaders for the grade
            native_result = _native_check(host.fqdn, s, expected, timeout, user_agent)
            sh_result = _securityheaders_check(host.fqdn, s, expected, timeout)
            if native_result:
                result = native_result
                if sh_result and sh_result.grade:
                    result.grade = sh_result.grade
                    result.source = "both"
            elif sh_result:
                result = sh_result

        if result:
            break

    if result:
        host.headers = result

    return host


def run_headers(
    store_path: Path,
    scheme: str = "https",
    source: str = "native",
    timeout: int = 10,
    user_agent: str | None = None,
    expected_path: str | None = None,
    force: bool = False,
) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    expected = _load_expected(expected_path)
    ua = user_agent or DEFAULT_UA

    # Filter to hosts that resolved (unless --force)
    targets = []
    for host in hosts.values():
        if not force and (not host.dns or host.dns.nxdomain):
            continue
        # Skip hosts with no resolved IPs (timeout/servfail with no records)
        if not force and host.dns and not host.dns.resolved_ips:
            continue
        targets.append(host)

    logger.info("Checking headers on %d hosts (source=%s, scheme=%s)", len(targets), source, scheme)

    checked = 0
    for host in targets:
        host = _check_host(host, scheme, source, expected, timeout, ua)
        hosts[host.fqdn] = host
        checked += 1

        # Rate limit for securityheaders.com
        if source in ("securityheaders", "both"):
            time.sleep(SECURITYHEADERS_RATE_LIMIT)

        if checked % 25 == 0:
            logger.info("Progress: %d/%d checked", checked, len(targets))

    save_store(store_path, hosts)

    success_count = sum(1 for h in targets if h.headers is not None)
    logger.info("Headers complete: %d/%d hosts got results", success_count, len(targets))
