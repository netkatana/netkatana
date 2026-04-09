# netkatana

HTTP header, TLS certificate, and DNS security scanner.

## Project structure

```
src/netkatana/
├── types.py           # Core types: Severity, Finding, StrictTransportSecurityHeader, TlsResult, DnsResult, HttpRule, TlsRule, DnsRule
├── scanners.py        # Rule runners: HttpScanner, TlsScanner, DnsScanner
├── cli.py             # Click CLI: `http`, `tls`, and `dns` commands
├── formatters.py      # Output: VerboseFormatter, JsonlFormatter, JsonFormatter, TableFormatter
├── http.py            # HTTP client with manual redirect following and typed redirect exceptions
├── utils.py           # Helpers: extract_host(), parse_strict_transport_security_header()
├── rules.py           # Rule registry: code, severity, detail, validator
└── validators/
    ├── dns.py         # DNS validators
    ├── tls.py         # TLS validators
    └── http/
        └── headers.py # HTTP header validators
```

## Rules

`src/netkatana/rules.py` is the source of truth for implemented checks. Each rule defines:

- `code`
- `severity`
- `detail`
- `validator`

`TODO.md` lists planned checks grouped by category.

## Key abstractions

**`Finding`** — result of a single rule evaluation. Fields: `host`, `code`, `severity`, `message`, `detail`, `metadata`.

**`Severity`** — `PASS | NOTICE | WARNING | CRITICAL`. `PASS` means the check ran and found no issue. `return []` means the check was irrelevant or couldn't run.

**`HttpRule` / `TlsRule` / `DnsRule`** — immutable rule definitions containing metadata plus a validator function.

**Validators** — async functions returning `str | None` or raising `ValidationError` / `ValidationErrors`.

**`HttpScanner` / `TlsScanner` / `DnsScanner`** — orchestrators that run rules against all targets concurrently and yield `Finding` objects.

## How validators work

- If the validator passes: return a PASS message string.
- If the validator is irrelevant or can't run: return `None`.
- If the validator finds one issue: raise `ValidationError`.
- If the validator finds multiple issues for the same rule: raise `ValidationErrors`.
- The scanner wraps validator output into `Finding` objects using rule metadata.

## Detail text conventions

The `detail` field appears on both PASS and FAIL findings. Follow these rules when writing detail text:

- **Informative, not prescriptive.** Explain what the header/directive/feature does and why it matters. Do not tell the user what to do ("use X", "set Y to Z").
- **Neutral with respect to outcome.** The same text appears on both PASS and FAIL findings. Avoid phrases that imply failure ("header absent", "is missing"). Write from the perspective of what the feature is and what happens when it is or isn't configured.
- **Concise.** One or two sentences. Prefer a semicolon to join cause and consequence over a long subordinate clause.
- **Single quotes, not backticks.** Use single quotes for header names, directive names, and values (e.g. 'max-age', 'unsafe-inline'). Backticks render in Markdown but not in the terminal.

## Adding a new rule

1. Add a validator function in the relevant module under `src/netkatana/validators/`.
2. Return `str | None`, or raise `ValidationError` / `ValidationErrors`.
3. Register the rule in `src/netkatana/rules.py` with `code`, `severity`, `detail`, and `validator`.
4. Add validator tests under `tests/validators/`.

## Testing conventions

- The `tests/` directory should mirror the `src/netkatana/` directory structure.
- Functions should be tested with function-based tests.
- Function test names should follow `test_<subject>_<scenario>`.
- Classes should be tested with class-based tests using `class Test<SubjectClass>:`.
- Test names for class methods should follow `test_<subject_method>_<scenario>`.

## Formatters

All formatters accept `show_passed: bool = False`. When `False` (default), `Severity.PASS` findings are dropped. Pass `--show-passed` on the CLI to include them.

## Development

```bash
make test      # run tests with coverage (uv run pytest -vv --cov=netkatana --cov-report=term-missing)
make lint      # check formatting and linting (ruff format --check + ruff check)
make format    # auto-fix formatting and linting (ruff format + ruff check --fix)
```

After making changes, always run `make format` followed by `make test` to ensure code is correctly formatted and all tests pass.
