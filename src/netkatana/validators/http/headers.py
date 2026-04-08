from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.utils import parse_content_security_policy, parse_strict_transport_security_header

_HSTS_MIN_MAX_AGE = 31_536_000  # one year
_CSP_HEADER = "content-security-policy"
_CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only"


def _csp_effective_sources(directives: dict[str, list[str]], directive: str) -> list[str] | None:
    if directive in directives:
        return directives[directive]

    return directives.get("default-src")


def _neutralizes_unsafe_inline(sources: list[str]) -> bool:
    return any(
        source.startswith("'nonce-")
        or source.startswith("'sha256-")
        or source.startswith("'sha384-")
        or source.startswith("'sha512-")
        or source == "'strict-dynamic'"
        for source in sources
    )


async def strict_transport_security_missing(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        raise ValidationError("Strict-Transport-Security (HSTS) missing")

    return "Strict-Transport-Security (HSTS) present"


async def strict_transport_security_invalid(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        return None

    value = response.headers["strict-transport-security"]

    try:
        parse_strict_transport_security_header(value)
    except ValueError as e:
        raise ValidationError("Strict-Transport-Security (HSTS) header is malformed", metadata={"value": value}) from e

    return "Strict-Transport-Security (HSTS) header is valid"


async def strict_transport_security_max_age_zero(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        return None

    value = response.headers["strict-transport-security"]

    try:
        parsed = parse_strict_transport_security_header(value)
    except ValueError:
        return None

    if parsed.max_age == 0:
        raise ValidationError("Strict-Transport-Security (HSTS) max-age is zero")

    return "Strict-Transport-Security (HSTS) max-age is non-zero"


async def strict_transport_security_max_age_low(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        return None

    value = response.headers["strict-transport-security"]

    try:
        parsed = parse_strict_transport_security_header(value)
    except ValueError:
        return None

    if parsed.max_age == 0:
        return None

    if parsed.max_age < _HSTS_MIN_MAX_AGE:
        raise ValidationError(
            "Strict-Transport-Security (HSTS) max-age is less than one year",
            metadata={"max_age": str(parsed.max_age)},
        )

    return "Strict-Transport-Security (HSTS) max-age meets minimum"


async def strict_transport_security_include_subdomains_missing(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        return None

    value = response.headers["strict-transport-security"]

    try:
        parsed = parse_strict_transport_security_header(value)
    except ValueError:
        return None

    if not parsed.include_subdomains:
        raise ValidationError("Strict-Transport-Security (HSTS) includeSubDomains missing")

    return "Strict-Transport-Security (HSTS) includeSubDomains present"


async def strict_transport_security_preload_not_eligible(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        return None

    value = response.headers["strict-transport-security"]

    try:
        parsed = parse_strict_transport_security_header(value)
    except ValueError:
        return None

    if not parsed.preload:
        return None

    if parsed.max_age < _HSTS_MIN_MAX_AGE or not parsed.include_subdomains:
        raise ValidationError("Strict-Transport-Security (HSTS) does not meet preload requirements")

    return "Strict-Transport-Security (HSTS) meets preload requirements"


async def content_security_policy_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        raise ValidationError("Content-Security-Policy (CSP) missing")

    return "Content-Security-Policy (CSP) present"


async def content_security_policy_unsafe_inline(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "'unsafe-inline'" not in effective:
        return "Content-Security-Policy (CSP) script-src does not contain 'unsafe-inline'"

    if _neutralizes_unsafe_inline(effective):
        return "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"

    raise ValidationError("Content-Security-Policy (CSP) script-src contains 'unsafe-inline'")


async def content_security_policy_report_only_unsafe_inline(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "'unsafe-inline'" not in effective:
        return "Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-inline'"

    if _neutralizes_unsafe_inline(effective):
        return "Content-Security-Policy-Report-Only (CSP) 'unsafe-inline' is neutralized by nonce or hash"

    raise ValidationError("Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-inline'")


async def content_security_policy_unsafe_eval(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "'unsafe-eval'" in effective:
        raise ValidationError("Content-Security-Policy (CSP) script-src contains 'unsafe-eval'")

    return "Content-Security-Policy (CSP) script-src does not contain 'unsafe-eval'"


async def content_security_policy_report_only_unsafe_eval(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "'unsafe-eval'" in effective:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-eval'")

    return "Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-eval'"
