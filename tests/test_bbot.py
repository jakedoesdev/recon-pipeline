"""Tests for BBOT output parsing and secrets YAML generation."""

import tempfile
from pathlib import Path

import yaml

from reconpipe.enum.bbot import (
    _parse_output_json,
    _parse_subdomains_txt,
    _write_secrets_yaml,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_output_json_filters_dns_name_in_scope():
    results = _parse_output_json(FIXTURES / "bbot_output.json", ["icanroll.com"])

    fqdns = [r[0] for r in results]
    sources = [r[1] for r in results]

    assert "icanroll.com" in fqdns
    assert "api.icanroll.com" in fqdns
    assert "route2.mx.cloudflare.net" not in fqdns  # affiliate, not in-scope
    assert "172.67.190.154" not in fqdns  # IP_ADDRESS type, not DNS_NAME


def test_parse_output_json_deduplicates():
    results = _parse_output_json(FIXTURES / "bbot_output.json", ["icanroll.com"])
    fqdns = [r[0] for r in results]
    assert fqdns.count("icanroll.com") == 1


def test_parse_output_json_strips_wildcards():
    results = _parse_output_json(FIXTURES / "bbot_output.json", ["icanroll.com"])
    fqdns = [r[0] for r in results]
    # *.icanroll.com should become icanroll.com (already present, so deduped)
    assert "*.icanroll.com" not in fqdns


def test_parse_output_json_module_attribution():
    results = _parse_output_json(FIXTURES / "bbot_output.json", ["icanroll.com"])
    source_map = {r[0]: r[1] for r in results}
    # First occurrence of icanroll.com is from TARGET module
    assert source_map["api.icanroll.com"] == "bbot:wayback"


def test_parse_subdomains_txt():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("sub1.example.com\nsub2.example.com\nsub1.example.com\n")
        f.flush()
        results = _parse_subdomains_txt(Path(f.name), "reconpipe-quiet")

    assert len(results) == 2
    assert results[0] == ("sub1.example.com", "bbot:reconpipe-quiet")
    assert results[1] == ("sub2.example.com", "bbot:reconpipe-quiet")


def test_write_secrets_yaml_empty_keys(monkeypatch):
    monkeypatch.setattr("reconpipe.enum.bbot.load_keys", lambda: {})

    with tempfile.TemporaryDirectory() as tmpdir:
        path = _write_secrets_yaml(Path(tmpdir))
        content = yaml.safe_load(path.read_text())
        assert content == {} or content is None


def test_write_secrets_yaml_with_keys(monkeypatch):
    monkeypatch.setattr(
        "reconpipe.enum.bbot.load_keys",
        lambda: {"shodan": "test_key_123", "github": "ghp_fake"},
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        path = _write_secrets_yaml(Path(tmpdir))
        content = yaml.safe_load(path.read_text())
        assert content["modules"]["shodan_dns"]["api_key"] == "test_key_123"
        assert content["modules"]["github_codesearch"]["api_key"] == "ghp_fake"
