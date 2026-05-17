from __future__ import annotations

import logging
import re
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
            resp = client.get(url, headers={"User-Agent": user_agent})

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

            return HeaderInfo(
                url_checked=str(resp.url),
                status_code=resp.status_code,
                present=present,
                missing=missing,
                page_title=page_title,
                meta_generator=meta_generator,
                technologies=technologies,
                cookies=cookies,
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


def _check_host(
    host: Host,
    scheme: str,
    expected: list[str],
    timeout: int,
    user_agent: str,
) -> Host:
    schemes = [scheme] if scheme != "both" else ["https", "http"]

    for s in schemes:
        result = _native_check(host.fqdn, s, expected, timeout, user_agent)
        if result:
            host.headers = result
            break

    return host


def run_headers(
    store_path: Path,
    scheme: str = "https",
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

    # Filter to hosts that resolved (unless --force), skip denied hosts
    targets = []
    for host in hosts.values():
        if is_out_of_scope(host):
            continue
        if not force and (not host.dns or host.dns.nxdomain):
            continue
        if not force and host.dns and not host.dns.resolved_ips:
            continue
        targets.append(host)

    logger.info("Checking headers on %d hosts (scheme=%s)", len(targets), scheme)

    checked = 0
    for host in targets:
        host = _check_host(host, scheme, expected, timeout, ua)
        hosts[host.fqdn] = host
        checked += 1

        if checked % 25 == 0:
            logger.info("Progress: %d/%d checked", checked, len(targets))

    save_store(store_path, hosts)

    success_count = sum(1 for h in targets if h.headers is not None)
    logger.info("Headers complete: %d/%d hosts got results", success_count, len(targets))
