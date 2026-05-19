from __future__ import annotations

import logging
import re

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..log import provenance

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
TIMEOUT = 30
MAX_ATTEMPTS = 4

_INVALID_CHARS = re.compile(r"[\s@!,;]")


class CrtshError(Exception):
    pass


@retry(
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError)),
    stop=stop_after_attempt(MAX_ATTEMPTS),
    wait=wait_exponential(multiplier=2, min=2, max=30),
    reraise=True,
)
def _fetch_json(domain: str) -> list[dict]:
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        resp = client.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"})
        resp.raise_for_status()
        return resp.json()


def query_crtsh(domain: str) -> list[str]:
    """Query crt.sh for subdomains. Raises CrtshError if all retries fail."""
    logger.info("crt.sh query for %s", domain)
    try:
        entries = _fetch_json(domain)
    except Exception as e:
        logger.warning("crt.sh failed for %s after retries: %s", domain, e)
        raise CrtshError(f"crt.sh failed for {domain}: {e}") from e

    raw_names: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name:
                raw_names.add(name)

    clean = _deduplicate(raw_names, domain)
    provenance(module="crtsh", action="ct_query", fqdn=domain,
               raw_entries=len(entries), raw_names=len(raw_names),
               deduped=len(clean))
    return clean


def _deduplicate(names: set[str], apex: str) -> list[str]:
    clean: list[str] = []
    for name in sorted(names):
        if _INVALID_CHARS.search(name):
            continue
        if not name.endswith(f".{apex}") and name != apex:
            continue
        clean.append(name)
    return clean
