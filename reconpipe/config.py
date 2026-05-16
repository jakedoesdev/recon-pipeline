from __future__ import annotations

import os
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def _config_dir() -> Path:
    return Path(os.environ.get("RECONPIPE_CONFIG_DIR", Path.home() / ".config" / "reconpipe"))


def load_config() -> dict:
    path = _config_dir() / "config.toml"
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def load_keys() -> dict[str, str]:
    path = _config_dir() / "keys.toml"
    if not path.exists():
        return {}
    with path.open("rb") as f:
        data = tomllib.load(f)
    return data.get("api_keys", {})


def get_key(name: str) -> str | None:
    env_var = f"RECONPIPE_{name.upper()}_KEY"
    val = os.environ.get(env_var)
    if val:
        return val
    keys = load_keys()
    return keys.get(name) or None
