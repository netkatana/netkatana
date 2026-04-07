# netkatana

HTTP header, TLS certificate, and DNS security scanner.

## Project structure

```
src/netkatana/
├── models.py          # Core types: Severity, Finding, HostFinding, AbstractHttpCheck, AbstractTlsCheck, TlsResult
├── scanners.py        # Orchestrators: HttpScanner, TlsScanner
├── cli.py             # Click CLI: `http` and `tls` commands
├── formatters.py      # Output: VerboseFormatter, JsonlFormatter, JsonFormatter, TableFormatter
├── http.py            # HTTP client with manual redirect following and typed redirect exceptions
├── utils.py           # extract_host() helper
└── checks/
    ├── http/
    │   └── headers.py # HTTP header checks
    └── tls.py         # TLS certificate and version checks
```

## Checks

`CHECKS.md` is the authoritative table of all implemented and planned checks across HTTP, TLS, DNS, and Response categories. Update it when adding or changing checks.

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

1. Subclass `AbstractHttpCheck` or `AbstractTlsCheck` in the relevant `checks/` file.
2. Implement `async def check(...)` returning `list[Finding]`.
3. Register the check in `cli.py`.

## Formatters

All formatters accept `show_passed: bool = False`. When `False` (default), `Severity.PASS` findings are silently dropped. Pass `--show-passed` on the CLI to include them.

## Development

```bash
make test      # run tests with coverage (uv run pytest -vv --cov=netkatana --cov-report=term-missing)
make lint      # check formatting and linting (ruff format --check + ruff check)
make format    # auto-fix formatting and linting (ruff format + ruff check --fix)
```
