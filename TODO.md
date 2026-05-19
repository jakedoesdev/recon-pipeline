# TODO

1. ~~**Skip already-processed hosts by default**~~ — Done. `headers`, `tls`, `rdap`, and `reverse` skip hosts with existing data. `--refresh` flag overrides.

2. ~~**Graceful exits with intermediate saves**~~ — Done. All network modules (`headers`, `tls`, `resolve`, `reverse`) have periodic flush every 25 hosts/IPs + SIGINT handler that finishes in-flight requests and saves progress.

3. ~~**Native scope enforcement after enum**~~ — Done. `enum` and `pipeline` validate scope files before enumeration starts. If no `--allow` is provided, previews up to 5 wildcard entries and offers to auto-generate `allow.txt` (with `*.rootdomain.tld` per target) and an empty `deny.txt`. `--auto-scope` flag skips the prompt. Scope runs automatically after enum completes.

4. ~~**Resilient crt.sh with deferred retry**~~ — Partial. `query_crtsh` now raises `CrtshError` on failure (after existing 4-attempt retry). Failed domains are saved to `crtsh-rescan.txt` next to the store, and a reminder with a ready-to-use re-run command is printed at the end of `enum` and `pipeline`. Automatic re-scanning not yet implemented.

5. **`rp add` — manual host injection** — Define a flow for adding one or more hosts directly to the store for processing by downstream modules without running enum. Works in tandem with the crt.sh retry and SAN rescan workflows: after initial scanning completes, a user can send hosts through one or more pipeline phases. Useful for subdomains discovered out-of-band, SAN-discovered hosts, or manual additions. Should accept a file or inline list of FQDNs and create store records with `discovery_sources: ["manual"]`.

6. **SAN-discovered host rescan** — When `analyze` flags `sans_new_subdomains`, save those FQDNs to a `sans-rescan.txt` file for potential re-scanning and addition to the store. Should integrate with `rp add` and the crt.sh retry flow so newly discovered domains/subdomains are added to the store and processed through all modules.

7. **Private IP extraction from headers/errors** — During `headers` (or `resolve`), check Location headers, error pages, response bodies, and other likely sources for leaked private IP addresses. Record each discovered private IP along with where it was found (which header, response body pattern, etc.) in the store. Flag the host appropriately. Goal: all private IPs exposed publicly by a domain/subdomain are captured, not just IPs from DNS resolution.

8. **Infrastructure ownership bucketing** — Sort hosts into buckets: likely client/target-controlled, CDN/proxy front-ends, and out-of-scope SaaS services. Primary bucket should be things the client likely owns/controls directly. Could add more buckets as needed. Include bucket assignment in report output or integrate into an existing module (likely `analyze`). Goal: know what entity or group of related entities owns the infrastructure behind each host.

9. **Clean output for tool ingestion** — Hosts that resolve to private IPs should not appear in `subs`, `subs-ips`, or `ips` output views. Private IPs should not appear in `ips` output. IPv6 addresses should be excluded from `subs` and `subs-ips` output (users query IPv6 directly when needed). Private-IP hosts and IPv6 data get their own dedicated output options. Goal: `subs`, `subs-ips`, and `ips` outputs are ready to feed directly into Nessus or other scanning tools without manual filtering.

10. **Proper IP sorting by octets** — When outputting IPs in any module or report view, sort by octets numerically (e.g., `4.13.x.x` < `4.56.x.x` < `12.32.x.x`), not lexicographically by first digit. Applies to `ips` view, `subs-ips` view, and any other IP-ordered output.

11. **WPScan integration** — Add an `rp wpscan` module with API key integration. Identify WordPress hosts from `headers` technology detection (no path fuzzing or endpoint probing for identification). Store complete wpscan output alongside the store (as enum does with bbot output). Capture in the store: WordPress version, theme and version, all identified plugins and versions, identified vulnerabilities/CVEs and what they affect, misconfigurations, exposed endpoints, and any other useful wpscan output. If full integration is too heavy, alternatively provide targeted wpscan commands to run against each detected WordPress host.

12. **Parallel execution for later modules** — `headers`, `tls`, `rdap`, and `reverse` write to different fields and could run concurrently after `resolve`. Requires field-level merging on write (each module only touches its own slice of the record).

13. **Built-in query system** — Replace complex jq one-liners with `rp query` supporting common filters as flags (e.g. `--flag stale_cname`, `--apex tesla.com`, `--ip 1.2.3.4`, `--severity critical,high`). Consider SQLite export as an alternative for ad-hoc queries.

14. **Selective refresh** — `--refresh-host <fqdn>` or `--refresh-host <file>` to re-check specific hosts instead of all-or-nothing. Useful for re-checking a single host after a change without re-running the full module.

15. ~~**Progress indicators for long modules**~~ — Done. All network modules (`resolve`, `reverse`, `headers`, `tls`) log progress every 25 hosts/IPs.

16. ~~**Structured logging**~~ — Done. Centralized `setup_logging` in `log.py` with `-v` (DEBUG), `-q` (WARNING), and `--log-file` (file at DEBUG level) on the root CLI group. All per-subcommand `logging.basicConfig` removed. Provenance trail (`<store>.provenance.jsonl`) records raw evidence at every network request and decision point for future `rp verify` support.

17. ~~**Redirect URL tracking and scope filtering**~~ — Done. `headers` records full `redirect_chain`. `rp scope --redirect-deny <file>` excludes hosts whose redirect chain matches substring or regex patterns.

18. ~~**Flag exposed lower environments**~~ — Done. `analyze` flags `lower_env_exposed` (medium severity) via FQDN patterns (dev, staging, qa, uat, test, sandbox, preprod, internal, etc.) and page title keywords.

19. **Verify command** — `rp verify` takes a host and field (e.g. `rp verify -i store.jsonl --host app.example.com --field tls`) and re-runs the commands needed to reproduce that field's output. Saves verbose logging, full command outputs, raw responses, and intermediate data that the normal pipeline discards. Useful for validating findings before including them in a report, debugging unexpected results, and producing evidence artifacts.
