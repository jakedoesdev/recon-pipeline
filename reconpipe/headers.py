from __future__ import annotations

import asyncio
import collections
import logging
import re
import signal
from pathlib import Path

import httpx

from .models import HeaderInfo, Host, _now_iso
from .store import is_out_of_scope, load_store, save_store

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

CORS_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
]

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)
_META_GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
_META_GEN_ALT_RE = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', re.I
)

_BODY_TECH_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"wp-content/|wp-includes/|/wp-json/", re.I), "WordPress"),
    (re.compile(r"Drupal\.settings|/sites/default/files", re.I), "Drupal"),
    (re.compile(r"Joomla!", re.I), "Joomla"),
    (re.compile(r"/_next/|__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"/_nuxt/|__NUXT__", re.I), "Nuxt.js"),
    (re.compile(r'ng-version="|ng-app=', re.I), "Angular"),
    (re.compile(r"data-reactroot|__REACT_DEVTOOLS", re.I), "React"),
    (re.compile(r"cdn\.shopify\.com|Shopify\.shop", re.I), "Shopify"),
    (re.compile(r"squarespace\.com|sqsp\.net", re.I), "Squarespace"),
    (re.compile(r"static\.wixstatic\.com|wix-code-sdk", re.I), "Wix"),
    (re.compile(r"confluence-dashboard|ajs-version-number", re.I), "Confluence"),
    (re.compile(r"JIRA\.SessionStorage|jira-issue-key", re.I), "Jira"),
    (re.compile(r"gitlab-org/gitlab|gitlab-ce|gitlab-ee", re.I), "GitLab"),
    (re.compile(r"grafana-app|grafana\.bootData", re.I), "Grafana"),
    (re.compile(r'<title>Dashboard \[Jenkins\]|jenkins-crumb', re.I), "Jenkins"),
    (re.compile(r"kibana-body|kbn-version", re.I), "Kibana"),
    (re.compile(r"phpMyAdmin", re.I), "phpMyAdmin"),
    (re.compile(r"Welcome to nginx!", re.I), "nginx"),
    (re.compile(r"Apache Tomcat/", re.I), "Apache Tomcat"),
    (re.compile(r"<title>IIS Windows Server", re.I), "IIS"),
    (re.compile(r"laravel|csrf-token.*Laravel", re.I), "Laravel"),
    (re.compile(r"__GATSBY", re.I), "Gatsby"),
    (re.compile(r"hubspot\.com/hub/", re.I), "HubSpot"),
]


def _load_expected(path: str | None) -> list[str]:
    if not path:
        return DEFAULT_EXPECTED
    p = Path(path)
    if not p.exists():
        logger.warning("Expected headers file not found: %s, using defaults", path)
        return DEFAULT_EXPECTED
    return [line.strip() for line in p.read_text().splitlines() if line.strip()]


def _parse_body(body: str) -> tuple[str | None, str | None, list[str]]:
    title = None
    m = _TITLE_RE.search(body[:5000])
    if m:
        raw = m.group(1).strip()
        title = re.sub(r"\s+", " ", raw)[:200]

    generator = None
    m = _META_GEN_RE.search(body[:10000]) or _META_GEN_ALT_RE.search(body[:10000])
    if m:
        generator = m.group(1).strip()[:200]

    techs: list[str] = []
    seen: set[str] = set()
    for pattern, tech_name in _BODY_TECH_PATTERNS:
        if tech_name not in seen and pattern.search(body):
            techs.append(tech_name)
            seen.add(tech_name)

    return title, generator, techs


def _parse_cookies(resp: httpx.Response) -> list[dict]:
    cookies: list[dict] = []
    for key, val in resp.headers.multi_items():
        if key.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in val.split(";")]
        name = parts[0].split("=", 1)[0] if parts else ""
        if not name:
            continue
        attrs_lower = {p.strip().lower().split("=")[0] for p in parts[1:]}
        samesite = None
        for p in parts[1:]:
            if p.strip().lower().startswith("samesite="):
                samesite = p.strip().split("=", 1)[1]
                break
        cookies.append({
            "name": name,
            "secure": "secure" in attrs_lower,
            "httponly": "httponly" in attrs_lower,
            "samesite": samesite,
        })
    return cookies


async def _native_check(
    client: httpx.AsyncClient,
    fqdn: str,
    scheme: str,
    expected: list[str],
    user_agent: str,
) -> HeaderInfo | None:
    url = f"{scheme}://{fqdn}"
    headers_dict: dict[str, str] = {}

    try:
        resp = await client.get(url, headers={"User-Agent": user_agent})

        redirect_chain = [str(r.url) for r in resp.history]
        if redirect_chain:
            redirect_chain.append(str(resp.url))

        for key in expected + BONUS_HEADERS + CORS_HEADERS:
            val = resp.headers.get(key)
            if val:
                headers_dict[key.lower()] = val[:200]

        for key, val in resp.headers.items():
            k = key.lower()
            if k.startswith("x-") and k not in headers_dict:
                headers_dict[k] = val[:200]

        present = {k: v for k, v in headers_dict.items()}
        missing = [h for h in expected if h.lower() not in headers_dict]

        body = resp.text[:15000]
        page_title, meta_generator, technologies = _parse_body(body)
        cookies = _parse_cookies(resp)
        body_snippet = body[:5000] if body else None

        return HeaderInfo(
            url_checked=str(resp.url),
            status_code=resp.status_code,
            redirect_chain=redirect_chain,
            present=present,
            missing=missing,
            page_title=page_title,
            meta_generator=meta_generator,
            technologies=technologies,
            cookies=cookies,
            body_snippet=body_snippet,
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


async def _check_host(
    client: httpx.AsyncClient,
    host: Host,
    scheme: str,
    expected: list[str],
    user_agent: str,
) -> Host:
    schemes = [scheme] if scheme != "both" else ["https", "http"]

    for s in schemes:
        result = await _native_check(client, host.fqdn, s, expected, user_agent)
        if result:
            host.headers = result
            break

    return host


def _host_primary_ip(host: Host) -> str:
    if host.dns and host.dns.resolved_ips:
        return host.dns.resolved_ips[0].ip
    return host.fqdn


FLUSH_INTERVAL = 25
PER_IP_LIMIT = 3


async def _check_all(
    hosts: dict[str, Host],
    targets: list[Host],
    store_path: Path,
    scheme: str,
    expected: list[str],
    user_agent: str,
    timeout: int,
    concurrency: int,
) -> tuple[int, bool]:
    interrupted = False

    def _handle_sigint(signum, frame):
        nonlocal interrupted
        interrupted = True
        logger.warning("Interrupt received — finishing in-flight requests and saving progress")

    prev_handler = signal.signal(signal.SIGINT, _handle_sigint)

    global_sem = asyncio.Semaphore(concurrency)
    ip_sems: dict[str, asyncio.Semaphore] = collections.defaultdict(
        lambda: asyncio.Semaphore(PER_IP_LIMIT)
    )

    checked = 0

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, verify=False,
    ) as client:
        async def process(host: Host) -> Host:
            ip = _host_primary_ip(host)
            async with global_sem, ip_sems[ip]:
                return await _check_host(client, host, scheme, expected, user_agent)

        pending: set[asyncio.Task] = set()

        for host in targets:
            if interrupted:
                break
            task = asyncio.create_task(process(host))
            pending.add(task)

        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                try:
                    result = task.result()
                    hosts[result.fqdn] = result
                except Exception as e:
                    logger.debug("Task failed: %s", e)
                checked += 1
                if checked % FLUSH_INTERVAL == 0:
                    logger.info("Progress: %d/%d checked", checked, len(targets))
                    save_store(store_path, hosts)

    signal.signal(signal.SIGINT, prev_handler)
    return checked, interrupted


def run_headers(
    store_path: Path,
    scheme: str = "https",
    timeout: int = 10,
    user_agent: str | None = None,
    expected_path: str | None = None,
    force: bool = False,
    refresh: bool = False,
    concurrency: int = 20,
) -> None:
    hosts = load_store(store_path)
    if not hosts:
        logger.warning("No hosts in store")
        return

    expected = _load_expected(expected_path)
    ua = user_agent or DEFAULT_UA

    # Filter to hosts that resolved (unless --force), skip denied hosts
    skipped = 0
    targets = []
    for host in hosts.values():
        if is_out_of_scope(host):
            continue
        if not refresh and host.headers is not None:
            skipped += 1
            continue
        if not force and (not host.dns or host.dns.nxdomain):
            continue
        if not force and host.dns and not host.dns.resolved_ips:
            continue
        targets.append(host)

    if skipped:
        logger.info("Skipping %d hosts with existing header data (use --refresh to re-check)", skipped)
    logger.info("Checking headers on %d hosts (scheme=%s, concurrency=%d, per-IP limit=%d)",
                len(targets), scheme, concurrency, PER_IP_LIMIT)

    if not targets:
        return

    checked, interrupted = asyncio.run(_check_all(
        hosts=hosts,
        targets=targets,
        store_path=store_path,
        scheme=scheme,
        expected=expected,
        user_agent=ua,
        timeout=timeout,
        concurrency=concurrency,
    ))

    save_store(store_path, hosts)

    success_count = sum(1 for h in hosts.values() if h.headers is not None)
    if interrupted:
        logger.info("Headers interrupted: %d/%d hosts checked, progress saved", checked, len(targets))
    else:
        logger.info("Headers complete: %d/%d hosts got results", success_count, len(targets))
