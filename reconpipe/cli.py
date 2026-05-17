from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
import tldextract

from .enum.bbot import BbotError, run_bbot
from .enum.crtsh import query_crtsh
from .models import Host
from .report import report_combined, report_headers, report_ips, report_subs, report_subs_ips
from .store import upsert_hosts


@click.group()
@click.version_option(package_name="reconpipe")
def cli():
    """reconpipe — composable recon pipeline."""


@cli.command()
@click.option("-i", "--input", "input_path", required=True, help="JSONL store path")
@click.option("--view", type=click.Choice(["subs", "ips", "subs-ips", "headers", "combined"]), default="combined")
@click.option("--scope", default="in", help="Scope bucket(s): in, unmatched, out, all (comma-separated)")
@click.option("--flagged-only", is_flag=True, default=False)
@click.option("-o", "--output", default=None, help="Output file (default: stdout)")
@click.option("--format", "fmt", default=None, help="Output format override")
def report(input_path, view, scope, flagged_only, output, fmt):
    """Generate output views from the JSONL store."""
    scope_list = [s.strip() for s in scope.split(",")]

    if view == "subs":
        report_subs(input_path, scope_list, output, flagged_only=flagged_only)
    elif view == "ips":
        report_ips(input_path, scope_list, output, flagged_only=flagged_only)
    elif view == "subs-ips":
        report_subs_ips(input_path, scope_list, output, flagged_only=flagged_only)
    elif view == "headers":
        report_headers(input_path, scope_list, output, flagged_only=flagged_only)
    elif view == "combined":
        report_combined(input_path, scope_list, output, fmt=fmt or "json", flagged_only=flagged_only)
    else:
        click.echo(f"View '{view}' not yet implemented.", err=True)
        raise SystemExit(1)


@cli.command()
@click.option("-i", "--input", "input_path", required=True, help="File of root domains")
@click.option("--bbot/--no-bbot", default=True)
@click.option("--bbot-preset", default="reconpipe-quiet")
@click.option("--bbot-args", default=None)
@click.option("--bbot-silent", is_flag=True, default=False, help="Suppress BBOT terminal output")
@click.option("--crtsh/--no-crtsh", default=True)
@click.option("-o", "--output", "output_path", required=True, help="JSONL output path")
def enum(input_path, bbot, bbot_preset, bbot_args, bbot_silent, crtsh, output_path):
    """Subdomain enumeration (BBOT + crt.sh)."""
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr
    )

    domains = _read_domains(input_path)
    if not domains:
        click.echo("No domains found in input file.", err=True)
        raise SystemExit(1)

    all_hosts: list[Host] = []

    if crtsh:
        for domain in domains:
            subs = query_crtsh(domain)
            click.echo(f"[crtsh] {domain}: {len(subs)} subdomains", err=True)
            for fqdn in subs:
                ext = tldextract.extract(fqdn)
                apex = f"{ext.domain}.{ext.suffix}"
                all_hosts.append(Host(fqdn=fqdn, apex=apex, discovery_sources=["crtsh"]))

    if bbot:
        try:
            bbot_results = run_bbot(domains, preset=bbot_preset, extra_args=bbot_args, silent=bbot_silent)
            click.echo(f"[bbot:{bbot_preset}] {len(bbot_results)} subdomains", err=True)
            for fqdn, source in bbot_results:
                ext = tldextract.extract(fqdn)
                apex = f"{ext.domain}.{ext.suffix}"
                all_hosts.append(Host(fqdn=fqdn, apex=apex, discovery_sources=[source]))
        except BbotError as e:
            click.echo(f"[bbot] error: {e}", err=True)

    if all_hosts:
        store = upsert_hosts(Path(output_path), all_hosts)
        click.echo(f"Store: {len(store)} total hosts in {output_path}", err=True)
    else:
        click.echo("No subdomains discovered.", err=True)


def _read_domains(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    return [line.strip().lower() for line in lines if line.strip() and not line.startswith("#")]


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--resolvers", default="1.1.1.1,8.8.8.8,9.9.9.9")
@click.option("--asn-db", default=None)
@click.option("--country-db", default=None)
@click.option("--wildcard-detect/--no-wildcard-detect", default=True)
@click.option("--concurrency", default=50, type=int)
def resolve(input_path, resolvers, asn_db, country_db, wildcard_detect, concurrency):
    """DNS resolution with private-IP detection."""
    from .resolve import run_resolve

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr
    )

    resolver_list = [r.strip() for r in resolvers.split(",")]
    run_resolve(
        store_path=Path(input_path),
        resolvers=resolver_list,
        concurrency=concurrency,
        wildcard_detect=wildcard_detect,
        asn_db=asn_db,
        country_db=country_db,
    )


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--scheme", type=click.Choice(["https", "http", "both"]), default="https")
@click.option("--timeout", default=10, type=int)
@click.option("--user-agent", default=None)
@click.option("--expected", default=None, help="Path to expected-headers file")
@click.option("--force", is_flag=True, default=False, help="Check even unresolved hosts")
def headers(input_path, scheme, timeout, user_agent, expected, force):
    """Security header checks."""
    from .headers import run_headers

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr
    )

    run_headers(
        store_path=Path(input_path),
        scheme=scheme,
        timeout=timeout,
        user_agent=user_agent,
        expected_path=expected,
        force=force,
    )


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--allow", default=None, help="Allow-list file")
@click.option("--deny", default=None, help="Deny-list file")
def scope(input_path, allow, deny):
    """Tag hosts with scope status."""
    from .scope import run_scope

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr
    )

    run_scope(
        store_path=Path(input_path),
        allow_path=allow,
        deny_path=deny,
    )


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--expected-country", default=None)
@click.option("--takeover-fingerprints", default=None)
@click.option("--enrich-online/--no-enrich-online", default=False)
def analyze(input_path, expected_country, takeover_fingerprints, enrich_online):
    """Anomaly detection and takeover checks."""
    from .analyze import run_analyze

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr
    )

    run_analyze(
        store_path=Path(input_path),
        expected_country=expected_country,
        fingerprints_path=takeover_fingerprints,
        enrich_online=enrich_online,
    )


@cli.command()
@click.option("-i", "--input", "input_path", required=True, help="File of root domains")
@click.option("-o", "--output", "output_path", required=True, help="JSONL store path")
@click.option("--bbot/--no-bbot", default=True)
@click.option("--bbot-preset", default="reconpipe-quiet")
@click.option("--bbot-silent", is_flag=True, default=False)
@click.option("--crtsh/--no-crtsh", default=True)
@click.option("--resolvers", default="1.1.1.1,8.8.8.8,9.9.9.9")
@click.option("--concurrency", default=50, type=int)
@click.option("--scheme", type=click.Choice(["https", "http", "both"]), default="https")
@click.option("--allow", default=None, help="Allow-list file for scope")
@click.option("--deny", default=None, help="Deny-list file for scope")
@click.option("--expected-country", default=None)
@click.option("--enrich-online/--no-enrich-online", default=False)
def pipeline(
    input_path, output_path, bbot, bbot_preset, bbot_silent, crtsh,
    resolvers, concurrency, scheme, allow, deny,
    expected_country, enrich_online,
):
    """Run full pipeline: enum → resolve → headers → scope → analyze."""
    from .analyze import run_analyze
    from .headers import run_headers
    from .resolve import run_resolve
    from .scope import run_scope

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr
    )

    store = Path(output_path)

    # 1. Enum
    click.echo("━━━ Phase: enum ━━━", err=True)
    domains = _read_domains(input_path)
    if not domains:
        click.echo("No domains found in input file.", err=True)
        raise SystemExit(1)

    all_hosts: list[Host] = []
    if crtsh:
        for domain in domains:
            from .enum.crtsh import query_crtsh
            subs = query_crtsh(domain)
            click.echo(f"[crtsh] {domain}: {len(subs)} subdomains", err=True)
            for fqdn in subs:
                import tldextract
                ext = tldextract.extract(fqdn)
                apex = f"{ext.domain}.{ext.suffix}"
                all_hosts.append(Host(fqdn=fqdn, apex=apex, discovery_sources=["crtsh"]))

    if bbot:
        try:
            bbot_results = run_bbot(domains, preset=bbot_preset, silent=bbot_silent)
            click.echo(f"[bbot:{bbot_preset}] {len(bbot_results)} subdomains", err=True)
            for fqdn, source in bbot_results:
                import tldextract
                ext = tldextract.extract(fqdn)
                apex = f"{ext.domain}.{ext.suffix}"
                all_hosts.append(Host(fqdn=fqdn, apex=apex, discovery_sources=[source]))
        except BbotError as e:
            click.echo(f"[bbot] error: {e}", err=True)

    if all_hosts:
        from .store import upsert_hosts
        result = upsert_hosts(store, all_hosts)
        click.echo(f"Store: {len(result)} total hosts", err=True)
    else:
        click.echo("No subdomains discovered.", err=True)
        raise SystemExit(1)

    # 2. Resolve
    click.echo("━━━ Phase: resolve ━━━", err=True)
    resolver_list = [r.strip() for r in resolvers.split(",")]
    run_resolve(store_path=store, resolvers=resolver_list, concurrency=concurrency)

    # 3. Headers
    click.echo("━━━ Phase: headers ━━━", err=True)
    run_headers(store_path=store, scheme=scheme)

    # 4. Scope
    if allow or deny:
        click.echo("━━━ Phase: scope ━━━", err=True)
        run_scope(store_path=store, allow_path=allow, deny_path=deny)
    else:
        click.echo("━━━ Phase: scope (skipped — no allow/deny files) ━━━", err=True)

    # 5. Analyze
    click.echo("━━━ Phase: analyze ━━━", err=True)
    run_analyze(
        store_path=store,
        expected_country=expected_country,
        enrich_online=enrich_online,
    )

    click.echo(f"━━━ Pipeline complete: {store} ━━━", err=True)


@cli.command()
@click.option("--old", required=True, help="Earlier JSONL snapshot")
@click.option("--new", required=True, help="Current JSONL snapshot")
@click.option("--scope", default="in")
@click.option("-o", "--output", default=None)
@click.option("--format", "fmt", type=click.Choice(["text", "json", "csv"]), default="text")
def diff(old, new, scope, output, fmt):
    """Diff two JSONL snapshots."""
    from .diff import run_diff

    run_diff(old_path=old, new_path=new, scope=scope, output=output, fmt=fmt)
