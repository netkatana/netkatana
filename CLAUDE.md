# netkatana

HTTP header, TLS certificate, and DNS security scanner.

## Project structure

```
src/netkatana/
├── types.py           # Core types: Severity, Finding, HostFinding, StrictTransportSecurityHeader, AbstractHttpCheck, AbstractTlsCheck, TlsResult, DnsResult
├── scanners.py        # Orchestrators: HttpScanner, TlsScanner, DnsScanner
├── cli.py             # Click CLI: `http`, `tls`, and `dns` commands
├── formatters.py      # Output: VerboseFormatter, JsonlFormatter, JsonFormatter, TableFormatter
├── http.py            # HTTP client with manual redirect following and typed redirect exceptions
├── utils.py           # Helpers: extract_host(), parse_strict_transport_security_header()
└── checks/
    ├── __init__.py    # Exposes http_checks, tls_checks, dns_checks lists consumed by cli.py
    ├── config.py      # Loads checks.toml, provides get_detail(code) and get_severity(code)
    ├── http/
    │   └── headers.py # HTTP header checks
    ├── tls.py         # TLS certificate and version checks
    └── dns.py         # DNS checks (SPF, DMARC, ...)
```

## Checks

`checks.toml` (project root) is the source of truth for `detail` and `severity` of all implemented checks. Each entry uses the check code as the table key.

`TODO.md` lists planned checks grouped by category.

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

## Detail text conventions

The `detail` field appears on both PASS and FAIL findings. Follow these rules when writing detail text:

- **Informative, not prescriptive.** Explain what the header/directive/feature does and why it matters. Do not tell the user what to do ("use X", "set Y to Z").
- **Neutral with respect to outcome.** The same text appears on both PASS and FAIL findings. Avoid phrases that imply failure ("header absent", "is missing"). Write from the perspective of what the feature is and what happens when it is or isn't configured.
- **Concise.** One or two sentences. Prefer a semicolon to join cause and consequence over a long subordinate clause.
- **Single quotes, not backticks.** Use single quotes for header names, directive names, and values (e.g. 'max-age', 'unsafe-inline'). Backticks render in Markdown but not in the terminal.

## Adding a new check

1. Add an entry to `checks.toml` with `detail` and `severity` (the failure severity).
2. Subclass `AbstractHttpCheck`, `AbstractTlsCheck`, or `AbstractDnsCheck` in the relevant `checks/` file.
3. Implement `async def check(...)` returning `list[Finding]`. Use `get_detail(code)` and `get_severity(code)` from `checks/config.py`; use `Severity.PASS` directly for pass findings.
4. Add the import and append an instance to the appropriate list in `checks/__init__.py`.

## Formatters

All formatters accept `show_passed: bool = False`. When `False` (default), `Severity.PASS` findings are silently dropped. Pass `--show-passed` on the CLI to include them.

## Development

```bash
make test      # run tests with coverage (uv run pytest -vv --cov=netkatana --cov-report=term-missing)
make lint      # check formatting and linting (ruff format --check + ruff check)
make format    # auto-fix formatting and linting (ruff format + ruff check --fix)
```

After making changes, always run `make format` followed by `make test` to ensure code is correctly formatted and all tests pass.
