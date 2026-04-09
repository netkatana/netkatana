# netkatana Agent Guide

This repository is a security scanner for HTTP headers, TLS configuration, and DNS records.

`src/netkatana/rules.py` is the source of truth for implemented checks. When adding or changing a rule, update code, tests, and rule metadata together.

## What To Keep In Sync

- Validators live under `src/netkatana/validators/`.
- Shared parsing or normalization logic belongs in `src/netkatana/utils.py`.
- Typed parsed-header results belong in `src/netkatana/types.py` when a validator benefits from structured data.
- Rules are registered in `src/netkatana/rules.py`.
- Validator tests live under `tests/validators/`.
- Parser/helper tests live in `tests/test_utils.py`.
- Cross-rule invariants belong in `tests/test_rules.py`.
- User-facing lists of implemented checks should be updated in `README.md`.

## How Rules Work

Each rule has:

- `code`
- `severity`
- `detail`
- `validator`

Validators are async functions that:

- return a string for a PASS finding
- return `None` when the rule is not applicable or cannot run
- raise `ValidationError` for one finding
- raise `ValidationErrors` for multiple findings from one rule

The scanner layer converts validator output into `Finding` objects using the metadata in `rules.py`.

## Adding A New Rule

1. Decide whether the logic is a parser/helper concern, a validator concern, or both.
2. If the header needs structured parsing, add a small parser in `src/netkatana/utils.py` and a typed result in `src/netkatana/types.py`.
3. Add one or more validators in the relevant validator module.
4. Register each validator as a rule in `src/netkatana/rules.py`.
5. Add focused tests for:
   - parser behavior
   - validator pass/fail behavior
   - rule-level invariants if applicable
6. Update `README.md` if a new rule code is introduced.

Prefer multiple narrow validators over one large validator when the project already models separate concerns as separate rules, such as:

- missing header
- invalid header syntax
- weaker but syntactically valid configurations

## HTTP Header Rule Conventions

- Header family parsers should be small and strict.
- Validators should reuse parser output instead of reimplementing parsing logic inline.
- Invalid header-value checks should usually return `None` when the header is absent.
- “Missing header” rules should raise a finding when the header is absent.
- “Weaker but valid value” rules should ignore absent or invalid headers and only flag parsed values they specifically care about.

## Report-Only Rules

- If an enforced rule has a report-only equivalent, keep severity aligned between the two.
- `tests/test_rules.py` contains an invariant test to catch severity drift between enforced and `_report_only_` HTTP rules.
- Report-only rules should still produce real findings when the configuration is not a useful rollout configuration.

## Detail Text

The `detail` field is shown for both PASS and FAIL findings. Write it so it works in both cases.

- Be informative, not prescriptive.
- Explain what the mechanism does and why it matters.
- Do not write failure-specific text like “header missing”.
- Keep it short: one or two sentences.
- Use single quotes for header names, directives, and values.

## Testing

Before finishing a change, run the smallest relevant tests first, then broader checks as needed.

Useful commands:

```bash
uv run pytest tests/test_utils.py
uv run pytest tests/test_rules.py
uv run pytest tests/validators/http/test_headers.py
uv run pytest tests/validators/test_tls.py
uv run pytest tests/validators/test_dns.py
make format
make test
```

## Practical Guidance

- Follow the naming patterns already used in `rules.py` and the validator test files.
- Keep rule codes stable and explicit.
- Do not add broad abstractions unless the existing code is already repeating the same pattern in multiple places.
- When introducing report-only checks, verify whether the browser/spec processing model actually gives that configuration effect before treating it as equivalent to enforced mode.
