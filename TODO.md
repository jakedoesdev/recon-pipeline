# TODO

1. ~~**Skip already-processed hosts by default**~~ — Done. `headers`, `tls`, `rdap`, and `reverse` skip hosts with existing data. `--refresh` flag overrides.

2. ~~**Graceful exits with intermediate saves**~~ — Done. All network modules (`headers`, `tls`, `resolve`, `reverse`) have periodic flush every 25 hosts/IPs + SIGINT handler that finishes in-flight requests and saves progress.

3. **Parallel execution for later modules** — `headers`, `tls`, `rdap`, and `reverse` write to different fields and could run concurrently after `resolve`. Requires field-level merging on write (each module only touches its own slice of the record).

4. **Built-in query system** — Replace complex jq one-liners with `rp query` supporting common filters as flags (e.g. `--flag stale_cname`, `--apex tesla.com`, `--ip 1.2.3.4`, `--severity critical,high`). Consider SQLite export as an alternative for ad-hoc queries.

5. ~~**Progress indicators for long modules**~~ — Done. All network modules (`resolve`, `reverse`, `headers`, `tls`) log progress every 25 hosts/IPs.

6. **Selective refresh** — `--refresh-host <fqdn>` or `--refresh-host <file>` to re-check specific hosts instead of all-or-nothing. Useful for re-checking a single host after a change without re-running the full module.

7. **Structured logging** — Configurable log levels (`-v` for DEBUG, `-q` for WARNING). Log to file option (`--log-file`). Consistent structured format across all modules. Currently each subcommand sets up its own `logging.basicConfig` independently.

8. ~~**Redirect URL tracking and scope filtering**~~ — Done. `headers` records full `redirect_chain`. `rp scope --redirect-deny <file>` excludes hosts whose redirect chain matches substring or regex patterns.

9. ~~**Flag exposed lower environments**~~ — Done. `analyze` flags `lower_env_exposed` (medium severity) via FQDN patterns (dev, staging, qa, uat, test, sandbox, preprod, internal, etc.) and page title keywords.

10. **Verify command** — `rp verify` takes a host and field (e.g. `rp verify -i store.jsonl --host app.example.com --field tls`) and re-runs the commands needed to reproduce that field's output. Saves verbose logging, full command outputs, raw responses, and intermediate data that the normal pipeline discards. Useful for validating findings before including them in a report, debugging unexpected results, and producing evidence artifacts.
