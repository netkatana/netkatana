# netkatana

HTTP header, TLS certificate, and DNS security scanner.

## Project structure

```
src/netkatana/
├── models.py          # Core types: Severity, Finding, HostFinding, StrictTransportSecurityHeader, AbstractHttpCheck, AbstractTlsCheck, TlsResult, DnsResult
├── scanners.py        # Orchestrators: HttpScanner, TlsScanner, DnsScanner
├── cli.py             # Click CLI: `http`, `tls`, and `dns` commands
├── formatters.py      # Output: VerboseFormatter, JsonlFormatter, JsonFormatter, TableFormatter
├── http.py            # HTTP client with manual redirect following and typed redirect exceptions
├── utils.py           # Helpers: extract_host(), parse_strict_transport_security_header()
└── checks/
    ├── http/
    │   └── headers.py # HTTP header checks
    ├── tls.py         # TLS certificate and version checks
    └── dns.py         # DNS checks (SPF, DMARC, ...)
```

## Checks

`CHECKS.md` is the authoritative table of all implemented and planned checks across HTTP, TLS, DNS, and Response categories. It also contains a References section linking to the relevant RFCs — useful when verifying check behaviour against the spec. Update it when adding or changing checks.

## Key abstractions

**`Finding`** — result of a single check. Fields: `code`, `severity`, `title`, `detail`, `metadata`.

**`Severity`** — `PASS | NOTICE | WARNING | CRITICAL`. `PASS` means the check ran and found no issue. `return []` means the check was irrelevant or couldn't run.

**`HostFinding`** — `Finding` paired with the host it came from. Emitted by scanners.

**`AbstractHttpCheck` / `AbstractTlsCheck`** — base classes for individual checks. Implement `async def check(...) -> list[Finding]`.

**`HttpScanner` / `TlsScanner`** — orchestrators that run all checks against all hosts concurrently and yield `HostFinding` objects.

## How checks work

- Each check returns `list[Finding]`.
- If the check passes: return one `Finding` with `severity=Severity.PASS`.
- If an issue is found: return one or more `Finding` objects with the appropriate severity.
- If the check can't run (e.g. missing data): return `[]`.
- PASS findings share the same `code` as their failure counterpart — `severity` distinguishes them.

## Adding a new check

1. Add the check to `CHECKS.md` first — it is the source of truth.
2. Subclass `AbstractHttpCheck`, `AbstractTlsCheck`, or `AbstractDnsCheck` in the relevant `checks/` file.
3. Implement `async def check(...)` returning `list[Finding]`.
4. Register the check in `cli.py`.

## Formatters

All formatters accept `show_passed: bool = False`. When `False` (default), `Severity.PASS` findings are silently dropped. Pass `--show-passed` on the CLI to include them.

## Development

```bash
make test      # run tests with coverage (uv run pytest -vv --cov=netkatana --cov-report=term-missing)
make lint      # check formatting and linting (ruff format --check + ruff check)
make format    # auto-fix formatting and linting (ruff format + ruff check --fix)
```

After making changes, always run `make format` followed by `make test` to ensure code is correctly formatted and all tests pass.
