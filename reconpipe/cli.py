from __future__ import annotations

from pathlib import Path

import click
import tldextract

from .enum.bbot import BbotError, run_bbot
from .enum.crtsh import CrtshError, query_crtsh
from .log import close_provenance, init_provenance, setup_logging
from .models import Host
from .report import report_combined, report_headers, report_ips, report_private, report_subs, report_subs_ips
from .scope import ensure_deny_file, generate_allow_file
from .store import upsert_hosts


@click.group()
@click.version_option(package_name="reconpipe")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Debug logging")
@click.option("-q", "--quiet", is_flag=True, default=False, help="Warning-only logging")
@click.option("--log-file", default=None, help="Also log to file (at DEBUG level)")
def cli(verbose, quiet, log_file):
    """reconpipe — composable recon pipeline."""
    verbosity = 1 if verbose else (-1 if quiet else 0)
    setup_logging(verbosity=verbosity, log_file=log_file)


@cli.command()
@click.option("-i", "--input", "input_path", required=True, help="JSONL store path")
@click.option("--view", type=click.Choice(["subs", "ips", "subs-ips", "private", "headers", "combined"]), default="combined")
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
    elif view == "private":
        report_private(input_path, scope_list, output, flagged_only=flagged_only)
    elif view == "headers":
        report_headers(input_path, scope_list, output, flagged_only=flagged_only)
    elif view == "combined":
        report_combined(input_path, scope_list, output, fmt=fmt or "json", flagged_only=flagged_only)
    else:
        click.echo(f"View '{view}' not yet implemented.", err=True)
        raise SystemExit(1)


@cli.command()
@click.option("-o", "--output", "output_path", required=True, help="JSONL store path")
@click.option("-i", "--input", "input_path", default=None, help="File of FQDNs to add (one per line)")
@click.option("--source", default="manual", help="Discovery source tag (default: manual)")
@click.argument("fqdns", nargs=-1)
def add(output_path, input_path, source, fqdns):
    """Add hosts to the store without running enumeration."""
    all_fqdns: list[str] = []

    if input_path:
        all_fqdns.extend(_read_domains(input_path))

    for fqdn in fqdns:
        cleaned = fqdn.strip().lower().rstrip(".")
        if cleaned and not cleaned.startswith("#"):
            all_fqdns.append(cleaned)

    if not all_fqdns:
        click.echo("No FQDNs provided. Use -i <file> and/or pass FQDNs as arguments.", err=True)
        raise SystemExit(1)

    seen: set[str] = set()
    hosts: list[Host] = []
    for fqdn in all_fqdns:
        if fqdn in seen:
            continue
        seen.add(fqdn)
        ext = tldextract.extract(fqdn)
        apex = f"{ext.domain}.{ext.suffix}"
        hosts.append(Host(fqdn=fqdn, apex=apex, discovery_sources=[source]))

    store = upsert_hosts(Path(output_path), hosts)
    click.echo(f"Added {len(hosts)} host(s) (store: {len(store)} total) to {output_path}", err=True)


@cli.command()
@click.option("-i", "--input", "input_path", required=True, help="File of root domains")
@click.option("--bbot/--no-bbot", default=True)
@click.option("--bbot-preset", default="reconpipe-quiet")
@click.option("--bbot-args", default=None)
@click.option("--bbot-silent", is_flag=True, default=False, help="Suppress BBOT terminal output")
@click.option("--crtsh/--no-crtsh", default=True)
@click.option("-o", "--output", "output_path", required=True, help="JSONL output path")
@click.option("--allow", default=None, help="Allow-list file for scope")
@click.option("--deny", default=None, help="Deny-list file for scope")
@click.option("--auto-scope", is_flag=True, default=False, help="Auto-generate allow.txt from targets without prompting")
def enum(input_path, bbot, bbot_preset, bbot_args, bbot_silent, crtsh, output_path, allow, deny, auto_scope):
    """Subdomain enumeration (BBOT + crt.sh)."""
    from .scope import run_scope

    domains = _read_domains(input_path)
    if not domains:
        click.echo("No domains found in input file.", err=True)
        raise SystemExit(1)

    allow, deny = _ensure_scope_files(input_path, domains, allow, deny, auto_scope)

    init_provenance(Path(output_path))

    all_hosts: list[Host] = []
    crtsh_failures: list[str] = []

    if crtsh:
        for domain in domains:
            try:
                subs = query_crtsh(domain)
                click.echo(f"[crtsh] {domain}: {len(subs)} subdomains", err=True)
                for fqdn in subs:
                    ext = tldextract.extract(fqdn)
                    apex = f"{ext.domain}.{ext.suffix}"
                    all_hosts.append(Host(fqdn=fqdn, apex=apex, discovery_sources=["crtsh"]))
            except CrtshError:
                click.echo(f"[crtsh] {domain}: FAILED — queued for rescan", err=True)
                crtsh_failures.append(domain)

    if bbot:
        try:
            bbot_results = run_bbot(domains, preset=bbot_preset, extra_args=bbot_args, silent=bbot_silent, store_path=Path(output_path))
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

    if allow:
        click.echo("━━━ Phase: scope ━━━", err=True)
        run_scope(store_path=Path(output_path), allow_path=allow, deny_path=deny)

    rescan_path = _write_crtsh_rescan(Path(output_path), crtsh_failures)
    if rescan_path:
        click.echo(f"\n⚠ {len(crtsh_failures)} domain(s) failed crt.sh — saved to {rescan_path}", err=True)
        click.echo(f"  Re-run with: rp enum -i {rescan_path} -o {output_path} --no-bbot", err=True)

    close_provenance()


def _read_domains(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    return [line.strip().lower() for line in lines if line.strip() and not line.startswith("#")]


def _has_entries(path: str | None) -> bool:
    if not path:
        return False
    p = Path(path)
    if not p.exists():
        return False
    lines = [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    return len(lines) > 0


def _preview_allow_entries(domains: list[str]) -> list[str]:
    seen: set[str] = set()
    entries: list[str] = []
    for domain in domains:
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            apex = f"{ext.domain}.{ext.suffix}"
            if apex not in seen:
                seen.add(apex)
                entries.append(f"*.{apex}")
    return entries


def _ensure_scope_files(
    targets_path: str,
    domains: list[str],
    allow_path: str | None,
    deny_path: str | None,
    auto_scope: bool,
) -> tuple[str | None, str | None]:
    """Validate and/or generate scope files before enum.

    Returns (allow_path, deny_path) to use for scoping after enum.
    """
    targets_dir = Path(targets_path).parent

    if _has_entries(allow_path):
        if not deny_path:
            deny_path = str(ensure_deny_file(targets_dir))
        return allow_path, deny_path

    entries = _preview_allow_entries(domains)

    if auto_scope:
        allow_path = str(generate_allow_file(domains, targets_dir))
        deny_path = deny_path or str(ensure_deny_file(targets_dir))
        return allow_path, deny_path

    click.echo("\nNo allow/deny scope files provided. These would be added to allow.txt:", err=True)
    for entry in entries[:5]:
        click.echo(f"  {entry}", err=True)
    if len(entries) > 5:
        click.echo(f"  ... and {len(entries) - 5} more", err=True)
    click.echo("", err=True)

    if click.confirm("Generate allow.txt and empty deny.txt?", default=True, err=True):
        allow_path = str(generate_allow_file(domains, targets_dir))
        deny_path = deny_path or str(ensure_deny_file(targets_dir))
        return allow_path, deny_path

    click.echo("Continuing without scope — all hosts will be 'unmatched'.", err=True)
    return None, deny_path


def _write_crtsh_rescan(store_path: Path, failures: list[str]) -> Path | None:
    if not failures:
        return None
    rescan_path = store_path.parent / "crtsh-rescan.txt"
    rescan_path.write_text("\n".join(failures) + "\n", encoding="utf-8")
    return rescan_path


def _write_sans_rescan(store_path: Path, fqdns: set[str]) -> Path | None:
    if not fqdns:
        return None
    rescan_path = store_path.parent / "sans-rescan.txt"
    rescan_path.write_text("\n".join(sorted(fqdns)) + "\n", encoding="utf-8")
    return rescan_path


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

    init_provenance(Path(input_path))
    resolver_list = [r.strip() for r in resolvers.split(",")]
    run_resolve(
        store_path=Path(input_path),
        resolvers=resolver_list,
        concurrency=concurrency,
        wildcard_detect=wildcard_detect,
        asn_db=asn_db,
        country_db=country_db,
    )
    close_provenance()


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--resolvers", default="1.1.1.1,8.8.8.8,9.9.9.9")
@click.option("--concurrency", default=50, type=int)
@click.option("--refresh", is_flag=True, default=False, help="Re-check all IPs, even those with existing PTR data")
def reverse(input_path, resolvers, concurrency, refresh):
    """Reverse DNS (PTR) lookups on discovered IPs."""
    from .reverse import run_reverse

    init_provenance(Path(input_path))
    resolver_list = [r.strip() for r in resolvers.split(",")]
    run_reverse(
        store_path=Path(input_path),
        resolvers=resolver_list,
        concurrency=concurrency,
        refresh=refresh,
    )
    close_provenance()


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--scheme", type=click.Choice(["https", "http", "both"]), default="https")
@click.option("--timeout", default=10, type=int)
@click.option("--user-agent", default=None)
@click.option("--expected", default=None, help="Path to expected-headers file")
@click.option("--force", is_flag=True, default=False, help="Check even unresolved hosts")
@click.option("--refresh", is_flag=True, default=False, help="Re-check all hosts, even those with existing header data")
@click.option("--concurrency", default=20, type=int, help="Max concurrent requests (default 20)")
def headers(input_path, scheme, timeout, user_agent, expected, force, refresh, concurrency):
    """Security header checks."""
    from .headers import run_headers

    init_provenance(Path(input_path))
    run_headers(
        store_path=Path(input_path),
        scheme=scheme,
        timeout=timeout,
        user_agent=user_agent,
        expected_path=expected,
        force=force,
        refresh=refresh,
        concurrency=concurrency,
    )
    close_provenance()


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--allow", default=None, help="Allow-list file")
@click.option("--deny", default=None, help="Deny-list file")
@click.option("--redirect-deny", default=None, help="Deny hosts whose redirect chain matches these patterns")
def scope(input_path, allow, deny, redirect_deny):
    """Tag hosts with scope status."""
    from .scope import run_scope

    init_provenance(Path(input_path))
    run_scope(
        store_path=Path(input_path),
        allow_path=allow,
        deny_path=deny,
        redirect_deny_path=redirect_deny,
    )
    close_provenance()


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--refresh", is_flag=True, default=False, help="Re-check all apex domains, even those with existing RDAP data")
def rdap(input_path, refresh):
    """RDAP registration lookups (per apex domain)."""
    from .rdap import run_rdap

    init_provenance(Path(input_path))
    run_rdap(store_path=Path(input_path), refresh=refresh)
    close_provenance()


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--port", default=443, type=int, help="TLS port to connect to")
@click.option("--refresh", is_flag=True, default=False, help="Re-check all hosts, even those with existing TLS data")
@click.option("--concurrency", default=30, type=int, help="Max concurrent connections (default 30)")
def tls(input_path, port, refresh, concurrency):
    """Collect live TLS certificate details."""
    from .tls import run_tls

    init_provenance(Path(input_path))
    run_tls(store_path=Path(input_path), port=port, refresh=refresh, concurrency=concurrency)
    close_provenance()


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--expected-country", default=None)
@click.option("--takeover-fingerprints", default=None)
@click.option("--enrich-online/--no-enrich-online", default=False)
def analyze(input_path, expected_country, takeover_fingerprints, enrich_online):
    """Anomaly detection and takeover checks."""
    from .analyze import run_analyze

    init_provenance(Path(input_path))
    san_new = run_analyze(
        store_path=Path(input_path),
        expected_country=expected_country,
        fingerprints_path=takeover_fingerprints,
        enrich_online=enrich_online,
    )

    rescan_path = _write_sans_rescan(Path(input_path), san_new)
    if rescan_path:
        click.echo(f"\n⚠ {len(san_new)} SAN-discovered FQDN(s) not in store — saved to {rescan_path}", err=True)

    close_provenance()


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
@click.option("--auto-scope", is_flag=True, default=False, help="Auto-generate allow.txt from targets without prompting")
@click.option("--expected-country", default=None)
@click.option("--rdap/--no-rdap", default=True)
@click.option("--wpscan/--no-wpscan", "run_wpscan_flag", default=True)
@click.option("--enrich-online/--no-enrich-online", default=False)
@click.option("--refresh", is_flag=True, default=False, help="Re-check hosts that already have data from prior runs")
def pipeline(
    input_path, output_path, bbot, bbot_preset, bbot_silent, crtsh,
    resolvers, concurrency, scheme, allow, deny, auto_scope,
    rdap, run_wpscan_flag, expected_country, enrich_online, refresh,
):
    """Run full pipeline: enum → scope → resolve → reverse → headers → tls → rdap → wpscan → analyze."""
    from .analyze import run_analyze
    from .headers import run_headers
    from .rdap import run_rdap
    from .resolve import run_resolve
    from .reverse import run_reverse
    from .scope import run_scope
    from .tls import run_tls
    from .wpscan import run_wpscan

    # Validate targets and scope files before any work
    domains = _read_domains(input_path)
    if not domains:
        click.echo("No domains found in input file.", err=True)
        raise SystemExit(1)

    allow, deny = _ensure_scope_files(input_path, domains, allow, deny, auto_scope)

    store = Path(output_path)
    init_provenance(store)

    # 1. Enum
    click.echo("━━━ Phase: enum ━━━", err=True)

    all_hosts: list[Host] = []
    crtsh_failures: list[str] = []
    if crtsh:
        for domain in domains:
            try:
                subs = query_crtsh(domain)
                click.echo(f"[crtsh] {domain}: {len(subs)} subdomains", err=True)
                for fqdn in subs:
                    ext = tldextract.extract(fqdn)
                    apex = f"{ext.domain}.{ext.suffix}"
                    all_hosts.append(Host(fqdn=fqdn, apex=apex, discovery_sources=["crtsh"]))
            except CrtshError:
                click.echo(f"[crtsh] {domain}: FAILED — queued for rescan", err=True)
                crtsh_failures.append(domain)

    if bbot:
        try:
            bbot_results = run_bbot(domains, preset=bbot_preset, silent=bbot_silent, store_path=store)
            click.echo(f"[bbot:{bbot_preset}] {len(bbot_results)} subdomains", err=True)
            for fqdn, source in bbot_results:
                ext = tldextract.extract(fqdn)
                apex = f"{ext.domain}.{ext.suffix}"
                all_hosts.append(Host(fqdn=fqdn, apex=apex, discovery_sources=[source]))
        except BbotError as e:
            click.echo(f"[bbot] error: {e}", err=True)

    if all_hosts:
        result = upsert_hosts(store, all_hosts)
        click.echo(f"Store: {len(result)} total hosts", err=True)
    else:
        click.echo("No subdomains discovered.", err=True)
        raise SystemExit(1)

    # 2. Scope (run early so downstream phases skip denied hosts)
    if allow:
        click.echo("━━━ Phase: scope ━━━", err=True)
        run_scope(store_path=store, allow_path=allow, deny_path=deny)
    else:
        click.echo("━━━ Phase: scope (skipped — user declined) ━━━", err=True)

    # 3. Resolve
    click.echo("━━━ Phase: resolve ━━━", err=True)
    resolver_list = [r.strip() for r in resolvers.split(",")]
    run_resolve(store_path=store, resolvers=resolver_list, concurrency=concurrency)

    # 4. Reverse DNS
    click.echo("━━━ Phase: reverse ━━━", err=True)
    run_reverse(store_path=store, resolvers=resolver_list, concurrency=concurrency, refresh=refresh)

    # 5. Headers
    click.echo("━━━ Phase: headers ━━━", err=True)
    run_headers(store_path=store, scheme=scheme, refresh=refresh, concurrency=min(concurrency, 20))

    # 6. TLS
    click.echo("━━━ Phase: tls ━━━", err=True)
    run_tls(store_path=store, refresh=refresh, concurrency=min(concurrency, 30))

    # 7. RDAP
    if rdap:
        click.echo("━━━ Phase: rdap ━━━", err=True)
        run_rdap(store_path=store, refresh=refresh)
    else:
        click.echo("━━━ Phase: rdap (skipped) ━━━", err=True)

    # 8. WPScan
    if run_wpscan_flag:
        click.echo("━━━ Phase: wpscan ━━━", err=True)
        run_wpscan(store_path=store, refresh=refresh)
    else:
        click.echo("━━━ Phase: wpscan (skipped) ━━━", err=True)

    # 9. Analyze
    click.echo("━━━ Phase: analyze ━━━", err=True)
    san_new = run_analyze(
        store_path=store,
        expected_country=expected_country,
        enrich_online=enrich_online,
    )

    sans_rescan_path = _write_sans_rescan(store, san_new)
    rescan_path = _write_crtsh_rescan(store, crtsh_failures)
    if rescan_path or sans_rescan_path:
        click.echo("", err=True)
    if rescan_path:
        click.echo(f"⚠ {len(crtsh_failures)} domain(s) failed crt.sh — saved to {rescan_path}", err=True)
        click.echo(f"  Re-run with: rp enum -i {rescan_path} -o {output_path} --no-bbot", err=True)
    if sans_rescan_path:
        click.echo(f"⚠ {len(san_new)} SAN-discovered FQDN(s) not in store — saved to {sans_rescan_path}", err=True)

    click.echo(f"━━━ Pipeline complete: {store} ━━━", err=True)
    close_provenance()


@cli.command()
@click.option("-i", "--input", "input_path", required=True)
@click.option("--refresh", is_flag=True, default=False, help="Re-scan all WordPress hosts, even those with existing WPScan data")
@click.option("--api-token", default=None, help="WPScan API token (overrides keys.toml)")
def wpscan(input_path, refresh, api_token):
    """Run WPScan against detected WordPress hosts."""
    from .wpscan import run_wpscan

    init_provenance(Path(input_path))
    run_wpscan(store_path=Path(input_path), refresh=refresh, api_token=api_token)
    close_provenance()


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
