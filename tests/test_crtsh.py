"""Tests for crt.sh response parsing and deduplication."""

from reconpipe.enum.crtsh import _deduplicate, query_crtsh


def test_deduplicate_strips_wildcards_and_invalid():
    raw = {
        "api.acme.com",
        "*.acme.com",       # wildcard — stripped to acme.com by caller, but raw set has it without *
        "dev.acme.com",
        "bad host.acme.com",  # space — invalid
        "other.example.com",  # wrong apex — filtered out
        "acme.com",           # apex itself — kept
        "UPPER.acme.com",     # already lowered by caller, but test the filter
        "test@acme.com",      # @ sign — invalid
    }
    result = _deduplicate(raw, "acme.com")
    assert "api.acme.com" in result
    assert "dev.acme.com" in result
    assert "acme.com" in result
    assert "bad host.acme.com" not in result
    assert "other.example.com" not in result
    assert "test@acme.com" not in result


def test_deduplicate_sorted_output():
    raw = {"z.acme.com", "a.acme.com", "m.acme.com"}
    result = _deduplicate(raw, "acme.com")
    assert result == ["a.acme.com", "m.acme.com", "z.acme.com"]


def test_deduplicate_empty_input():
    assert _deduplicate(set(), "acme.com") == []


def test_deduplicate_multiline_name_value_simulation():
    """Simulates what happens after splitting name_value on newlines."""
    raw = {
        "sub1.acme.com",
        "sub1.acme.com",  # duplicate — set handles it
        "sub2.acme.com",
        "acme.com",
    }
    result = _deduplicate(raw, "acme.com")
    assert len(result) == 3
    assert result == ["acme.com", "sub1.acme.com", "sub2.acme.com"]
