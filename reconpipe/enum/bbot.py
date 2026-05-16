from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

import yaml

from ..config import load_keys

logger = logging.getLogger(__name__)

PRESETS_DIR = Path(__file__).parent.parent / "presets"

BUILTIN_PRESETS = {
    "kitchen-sink": "kitchen-sink",
    "subdomain-enum": "subdomain-enum",
    "reconpipe-quiet": str(PRESETS_DIR / "reconpipe-quiet.yml"),
}


class BbotError(Exception):
    pass


def _write_secrets_yaml(tmpdir: Path) -> Path:
    """Write a BBOT secrets YAML from keys.toml. Returns path to the file."""
    keys = load_keys()
    secrets_path = tmpdir / "bbot_secrets.yml"

    bbot_keys: dict[str, dict] = {}
    key_module_map = {
        "shodan": "shodan_dns",
        "securitytrails": "securitytrails",
        "virustotal": "virustotal",
        "urlscan": "urlscan",
        "chaos": "chaos",
        "github": "github_codesearch",
    }

    for our_key, bbot_module in key_module_map.items():
        val = keys.get(our_key, "")
        if val:
            bbot_keys[bbot_module] = {"api_key": val}

    secrets = {"modules": bbot_keys} if bbot_keys else {}
    secrets_path.write_text(yaml.dump(secrets, default_flow_style=False), encoding="utf-8")
    return secrets_path


def _find_output_json(output_dir: Path) -> Path | None:
    """Find output.json in BBOT's output directory (may be nested under scan name)."""
    direct = output_dir / "output.json"
    if direct.exists():
        return direct

    for candidate in output_dir.rglob("output.json"):
        return candidate

    return None


def _find_subdomains_txt(output_dir: Path) -> Path | None:
    """Fallback: find subdomains.txt."""
    direct = output_dir / "subdomains.txt"
    if direct.exists():
        return direct

    for candidate in output_dir.rglob("subdomains.txt"):
        return candidate

    return None


def _parse_output_json(path: Path, target_domains: list[str]) -> list[tuple[str, str]]:
    """Parse output.json, return list of (fqdn, module) for in-scope DNS_NAME records."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if record.get("type") != "DNS_NAME":
                continue
            if record.get("scope_description") != "in-scope":
                continue

            host = record.get("host", "").lower().strip()
            module = record.get("module", "unknown").lower()

            if not host or host in seen:
                continue

            if host.startswith("*."):
                host = host[2:]

            seen.add(host)
            results.append((host, f"bbot:{module}"))

    return results


def _parse_subdomains_txt(path: Path, preset: str) -> list[tuple[str, str]]:
    """Fallback parser — no per-module attribution available."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()

    for line in path.read_text(encoding="utf-8").splitlines():
        host = line.strip().lower()
        if host and host not in seen:
            seen.add(host)
            results.append((host, f"bbot:{preset}"))

    return results


def run_bbot(
    targets: list[str],
    preset: str = "reconpipe-quiet",
    extra_args: str | None = None,
    silent: bool = False,
) -> list[tuple[str, str]]:
    """
    Run BBOT against targets with the given preset.
    Returns list of (fqdn, discovery_source) tuples.

    When silent=False (default), BBOT streams to the terminal and stdin
    is connected so the user can type interactive commands (e.g. "kill <module>").
    """
    preset_value = BUILTIN_PRESETS.get(preset, preset)

    with tempfile.TemporaryDirectory(prefix="reconpipe_bbot_") as tmpdir:
        tmpdir_path = Path(tmpdir)
        output_dir = tmpdir_path / "output"
        output_dir.mkdir()

        secrets_path = _write_secrets_yaml(tmpdir_path)

        cmd = [
            "bbot",
            "-t", *targets,
            "-p", preset_value,
            "-o", str(output_dir),
            "-n", "reconpipe",
            "-y",
        ]

        if silent:
            cmd.append("--silent")

        # Only pass secrets file if we have keys
        keys = load_keys()
        if keys:
            cmd.extend(["-c", f"secrets_file={secrets_path}"])

        if extra_args:
            cmd.extend(extra_args.split())

        logger.info("Running BBOT: %s", " ".join(cmd))

        try:
            if silent:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,
                )
                if result.returncode != 0:
                    logger.warning("BBOT exited with code %d: %s", result.returncode, result.stderr[:500])
            else:
                result = subprocess.run(cmd)
                if result.returncode != 0:
                    logger.warning("BBOT exited with code %d", result.returncode)
        except FileNotFoundError:
            raise BbotError("bbot not found on PATH. Install BBOT: pip install bbot")
        except subprocess.TimeoutExpired:
            raise BbotError("BBOT timed out after 1 hour")

        output_json = _find_output_json(output_dir)
        if output_json:
            logger.info("Parsing BBOT output.json: %s", output_json)
            return _parse_output_json(output_json, targets)

        subdomains_txt = _find_subdomains_txt(output_dir)
        if subdomains_txt:
            logger.info("Falling back to subdomains.txt: %s", subdomains_txt)
            return _parse_subdomains_txt(subdomains_txt, preset)

        logger.warning("No BBOT output found in %s", output_dir)
        if result.stderr:
            logger.debug("BBOT stderr: %s", result.stderr[:1000])
        return []
