"""Centralized logging and provenance trail for reconpipe.

The provenance log (``<store>.provenance.jsonl``) records raw evidence at
every network request and decision point so that ``rp verify`` can trace
any store field back to the response that produced it — without re-running
the request.
"""

from __future__ import annotations

import json
import logging
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def setup_logging(verbosity: int = 0, log_file: str | None = None) -> None:
    level = (
        logging.WARNING if verbosity < 0
        else logging.DEBUG if verbosity > 0
        else logging.INFO
    )

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    fmt = logging.Formatter("%(levelname)s %(name)s: %(message)s")

    stderr_h = logging.StreamHandler(sys.stderr)
    stderr_h.setLevel(level)
    stderr_h.setFormatter(fmt)
    root.addHandler(stderr_h)

    if log_file:
        file_fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        file_h = logging.FileHandler(log_file, encoding="utf-8")
        file_h.setLevel(logging.DEBUG)
        file_h.setFormatter(file_fmt)
        root.addHandler(file_h)


# ---------------------------------------------------------------------------
# Provenance trail
# ---------------------------------------------------------------------------

_prov_fh = None


def init_provenance(store_path: Path) -> None:
    global _prov_fh
    close_provenance()
    prov_path = store_path.parent / f"{store_path.stem}.provenance.jsonl"
    prov_path.parent.mkdir(parents=True, exist_ok=True)
    _prov_fh = prov_path.open("a", encoding="utf-8", buffering=1)


def provenance(*, module: str, action: str, fqdn: str | None = None,
               ip: str | None = None, **detail) -> None:
    if _prov_fh is None:
        return
    entry: dict = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "module": module,
        "action": action,
    }
    if fqdn is not None:
        entry["fqdn"] = fqdn
    if ip is not None:
        entry["ip"] = ip
    if detail:
        entry["detail"] = detail
    _prov_fh.write(json.dumps(entry, separators=(",", ":")) + "\n")


def flush_provenance() -> None:
    if _prov_fh is not None:
        _prov_fh.flush()


def close_provenance() -> None:
    global _prov_fh
    if _prov_fh is not None:
        _prov_fh.close()
        _prov_fh = None


@contextmanager
def provenance_context(store_path: Path):
    init_provenance(store_path)
    try:
        yield
    finally:
        close_provenance()
