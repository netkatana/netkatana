# netkatana Agent Guide

- `src/netkatana/rules.py` is the source of truth for implemented checks.
- Keep rule changes in sync across:
  - validators in `src/netkatana/validators/`
  - shared parsers/helpers in `src/netkatana/utils.py`
  - typed parsed-header results in `src/netkatana/types.py`
  - tests under `tests/`
  - `README.md` when new rule codes are added

## Validators

- Validators are async functions.
- Return a string for PASS.
- Return `None` when the rule is not applicable or cannot run.
- Raise `ValidationError` for one finding.
- Raise `ValidationErrors` for multiple findings.

## Rule Design

- Prefer small parsers in `utils.py` and reuse them from validators.
- Prefer multiple narrow rules over one broad rule:
  - missing header
  - invalid syntax
  - weaker but valid configuration
- If an enforced rule has a report-only equivalent, their severities must match.

## Detail Text

- `detail` is shown for both PASS and FAIL findings.
- Keep it short, informative, and not failure-specific.
- Use single quotes for header names, directives, and values.

## Tests

- `tests/` should mirror `src/netkatana/`.
- Examples:
  - `src/netkatana/validators/tls.py` -> `tests/validators/test_tls.py`
  - `src/netkatana/validators/http/headers.py` -> `tests/validators/http/test_headers.py`
  - `src/netkatana/utils.py` -> `tests/test_utils.py`
- Function tests should use `test_<subject_function_name>_<scenario>`.
- Class tests should use `Test<SubjectClassName>`.
- Method tests should use `test_<subject_method_name>_<scenario>`.
- Cross-rule invariants belong in `tests/test_rules.py`.
