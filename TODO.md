# TODO

1. ~~**Skip already-processed hosts by default**~~ — Done. `headers`, `tls`, `rdap`, and `reverse` skip hosts with existing data. `--refresh` flag overrides.

2. ~~**Graceful exits with intermediate saves**~~ — Done. All network modules (`headers`, `tls`, `resolve`, `reverse`) have periodic flush every 25 hosts/IPs + SIGINT handler that finishes in-flight requests and saves progress.

3. ~~**Native scope enforcement after enum**~~ — Done. `enum` and `pipeline` validate scope files before enumeration starts. If no `--allow` is provided, previews up to 5 wildcard entries and offers to auto-generate `allow.txt` (with `*.rootdomain.tld` per target) and an empty `deny.txt`. `--auto-scope` flag skips the prompt. Scope runs automatically after enum completes.

4. ~~**Resilient crt.sh with deferred retry**~~ — Partial. `query_crtsh` now raises `CrtshError` on failure (after existing 4-attempt retry). Failed domains are saved to `crtsh-rescan.txt` next to the store, and a reminder with a ready-to-use re-run command is printed at the end of `enum` and `pipeline`. Automatic re-scanning not yet implemented.

5. ~~**`rp add` — manual host injection**~~ — Done. `rp add -o store.jsonl` accepts FQDNs via `-i <file>` and/or positional args. Creates store records with `discovery_sources: ["manual"]` (customizable via `--source`). Merges with existing records. No network calls — designed to work with `sans-rescan.txt` and `crtsh-rescan.txt` for adding hosts discovered out-of-band.

6. ~~**SAN-discovered host rescan**~~ — Done. `analyze` saves SAN-discovered FQDNs to `sans-rescan.txt` next to the store. Integrates with `rp add` for adding them back to the store (e.g., `rp add -o store.jsonl -i sans-rescan.txt --source sans-rescan`).

7. ~~**Private IP extraction from headers/errors**~~ — Done. `headers` extracts private IPs from response headers (Location, Via, X-Forwarded-For, X-Real-IP, X-Backend-Server, and all X-* headers), redirect chain Location headers, and response body. Stored as `headers.leaked_ips[]` with ip, source, and detail context. `analyze` flags as `private_ip_leaked` (high severity).

8. **Infrastructure ownership bucketing** — Sort hosts into buckets: likely client/target-controlled, CDN/proxy front-ends, and out-of-scope SaaS services. Primary bucket should be things the client likely owns/controls directly. Could add more buckets as needed. Include bucket assignment in report output or integrate into an existing module (likely `analyze`). Goal: know what entity or group of related entities owns the infrastructure behind each host.

9. ~~**Clean output for tool ingestion**~~ — Partial. `subs` excludes hosts that resolve only to private IPs. `subs-ips` excludes private IP rows. `ips` already excluded private IPs. New `--view private` shows hosts with private IPs (fqdn,ip,record_type CSV). IPv6 filtering not yet implemented.

10. ~~**Proper IP sorting by octets**~~ — Done. `ips` view sorts by `ipaddress.ip_address` (numeric octets). `diff` IP comparisons also sort numerically. IPv6 addresses sort after IPv4.

11. ~~**WPScan integration**~~ — Done. `rp wpscan` module runs WPScan against WordPress hosts detected by `headers` technology fingerprinting. Subprocess wrapper with JSON parsing, API key via `keys.toml` (optional — warns if missing). Stores `WpscanInfo` on the host: wp_version, theme, plugins (with versions), vulnerabilities/CVEs, interesting findings. Raw JSON saved to `wpscan_out/`. Integrated into pipeline between rdap and analyze. `analyze` flags: `wp_vulns`, `wp_outdated`, `wp_theme_outdated`, `wp_plugins_outdated`.

12. **Parallel execution for later modules** — `headers`, `tls`, `rdap`, and `reverse` write to different fields and could run concurrently after `resolve`. Requires field-level merging on write (each module only touches its own slice of the record).

13. **Built-in query system** — Replace complex jq one-liners with `rp query` supporting common filters as flags (e.g. `--flag stale_cname`, `--apex tesla.com`, `--ip 1.2.3.4`, `--severity critical,high`). Consider SQLite export as an alternative for ad-hoc queries.

14. **Selective refresh** — `--refresh-host <fqdn>` or `--refresh-host <file>` to re-check specific hosts instead of all-or-nothing. Useful for re-checking a single host after a change without re-running the full module.

15. ~~**Progress indicators for long modules**~~ — Done. All network modules (`resolve`, `reverse`, `headers`, `tls`) log progress every 25 hosts/IPs.

16. ~~**Structured logging**~~ — Done. Centralized `setup_logging` in `log.py` with `-v` (DEBUG), `-q` (WARNING), and `--log-file` (file at DEBUG level) on the root CLI group. All per-subcommand `logging.basicConfig` removed. Provenance trail (`<store>.provenance.jsonl`) records raw evidence at every network request and decision point for future `rp verify` support.

17. ~~**Redirect URL tracking and scope filtering**~~ — Done. `headers` records full `redirect_chain`. `rp scope --redirect-deny <file>` excludes hosts whose redirect chain matches substring or regex patterns.

18. ~~**Flag exposed lower environments**~~ — Done. `analyze` flags `lower_env_exposed` (medium severity) via FQDN patterns (dev, staging, qa, uat, test, sandbox, preprod, internal, etc.) and page title keywords.

19. **Verify command** — `rp verify` takes a host and field (e.g. `rp verify -i store.jsonl --host app.example.com --field tls`) and re-runs the commands needed to reproduce that field's output. Saves verbose logging, full command outputs, raw responses, and intermediate data that the normal pipeline discards. Useful for validating findings before including them in a report, debugging unexpected results, and producing evidence artifacts.
