from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.utils import parse_content_security_policy, parse_strict_transport_security_header

_HSTS_MIN_MAX_AGE = 31_536_000  # one year
_CSP_HEADER = "content-security-policy"
_CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only"
_CORS_ALLOW_ORIGIN_HEADER = "access-control-allow-origin"
_CORS_ALLOW_CREDENTIALS_HEADER = "access-control-allow-credentials"
_CORS_ALLOW_METHODS_HEADER = "access-control-allow-methods"
_CORS_UNSAFE_METHODS = {"DELETE", "PATCH", "PUT"}
_CORS_MAX_AGE_HEADER = "access-control-max-age"
_CORS_MAX_AGE_EXCESSIVE = 86_400


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


async def content_security_policy_object_src_unsafe(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "object-src")

    if effective == ["'none'"]:
        return "Content-Security-Policy (CSP) object-src is restricted to 'none'"

    raise ValidationError("Content-Security-Policy (CSP) object-src is not restricted to 'none'")


async def content_security_policy_report_only_object_src_unsafe(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "object-src")

    if effective == ["'none'"]:
        return "Content-Security-Policy-Report-Only (CSP) object-src is restricted to 'none'"

    raise ValidationError("Content-Security-Policy-Report-Only (CSP) object-src is not restricted to 'none'")


async def content_security_policy_base_uri_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])

    if "base-uri" not in directives:
        raise ValidationError("Content-Security-Policy (CSP) base-uri is missing")

    return "Content-Security-Policy (CSP) base-uri is present"


async def content_security_policy_report_only_base_uri_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])

    if "base-uri" not in directives:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) base-uri is missing")

    return "Content-Security-Policy-Report-Only (CSP) base-uri is present"


async def content_security_policy_frame_ancestors_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])

    if "frame-ancestors" not in directives:
        raise ValidationError("Content-Security-Policy (CSP) frame-ancestors is missing")

    return "Content-Security-Policy (CSP) frame-ancestors is present"


async def content_security_policy_report_only_frame_ancestors_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])

    if "frame-ancestors" not in directives:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) frame-ancestors is missing")

    return "Content-Security-Policy-Report-Only (CSP) frame-ancestors is present"


async def content_security_policy_form_action_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])

    if "form-action" not in directives:
        raise ValidationError("Content-Security-Policy (CSP) form-action is missing")

    return "Content-Security-Policy (CSP) form-action is present"


async def content_security_policy_report_only_form_action_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])

    if "form-action" not in directives:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) form-action is missing")

    return "Content-Security-Policy-Report-Only (CSP) form-action is present"


async def content_security_policy_script_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) script-src is missing")

    return "Content-Security-Policy (CSP) script-src is present"


async def content_security_policy_report_only_script_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) script-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) script-src is present"


async def content_security_policy_script_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy (CSP) script-src is unrestricted")

    return "Content-Security-Policy (CSP) script-src is restricted"


async def content_security_policy_report_only_script_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) script-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) script-src is restricted"


async def content_security_policy_style_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "style-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) style-src is missing")

    return "Content-Security-Policy (CSP) style-src is present"


async def content_security_policy_style_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "style-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy (CSP) style-src is unrestricted")

    return "Content-Security-Policy (CSP) style-src is restricted"


async def content_security_policy_report_only_style_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "style-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) style-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) style-src is present"


async def content_security_policy_report_only_style_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "style-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) style-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) style-src is restricted"


async def content_security_policy_connect_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "connect-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) connect-src is missing")

    return "Content-Security-Policy (CSP) connect-src is present"


async def content_security_policy_connect_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "connect-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy (CSP) connect-src is unrestricted")

    return "Content-Security-Policy (CSP) connect-src is restricted"


async def content_security_policy_report_only_connect_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "connect-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) connect-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) connect-src is present"


async def content_security_policy_report_only_connect_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "connect-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) connect-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) connect-src is restricted"


async def access_control_allow_origin_wildcard(response: Response) -> str | None:
    if _CORS_ALLOW_ORIGIN_HEADER not in response.headers:
        return None

    if response.headers[_CORS_ALLOW_ORIGIN_HEADER].strip() == "*":
        raise ValidationError("Access-Control-Allow-Origin is wildcard (*)")

    return "Access-Control-Allow-Origin is not wildcard"


async def access_control_allow_origin_null(response: Response) -> str | None:
    if _CORS_ALLOW_ORIGIN_HEADER not in response.headers:
        return None

    if response.headers[_CORS_ALLOW_ORIGIN_HEADER].strip() == "null":
        raise ValidationError("Access-Control-Allow-Origin is null")

    return "Access-Control-Allow-Origin is not null"


async def access_control_allow_credentials_wildcard(response: Response) -> str | None:
    if _CORS_ALLOW_ORIGIN_HEADER not in response.headers:
        return None

    if response.headers[_CORS_ALLOW_ORIGIN_HEADER].strip() != "*":
        return None

    credentials = response.headers.get(_CORS_ALLOW_CREDENTIALS_HEADER, "").strip().lower()
    if credentials == "true":
        raise ValidationError("Access-Control-Allow-Origin is wildcard with credentials enabled")

    return "Access-Control-Allow-Origin wildcard does not enable credentials"


async def access_control_allow_credentials_invalid(response: Response) -> str | None:
    if _CORS_ALLOW_CREDENTIALS_HEADER not in response.headers:
        return None

    value = response.headers[_CORS_ALLOW_CREDENTIALS_HEADER].strip()
    if value.lower() == "true":
        return "Access-Control-Allow-Credentials has a valid value"

    raise ValidationError("Access-Control-Allow-Credentials has an invalid value", metadata={"value": value})


async def access_control_allow_methods_unsafe(response: Response) -> str | None:
    if _CORS_ALLOW_METHODS_HEADER not in response.headers:
        return None

    methods = {method.strip().upper() for method in response.headers[_CORS_ALLOW_METHODS_HEADER].split(",")}
    unsafe = methods & _CORS_UNSAFE_METHODS

    if unsafe:
        raise ValidationError(
            "Access-Control-Allow-Methods includes unsafe methods",
            metadata={"methods": ", ".join(sorted(unsafe))},
        )

    return "Access-Control-Allow-Methods does not include unsafe methods"


async def access_control_max_age_excessive(response: Response) -> str | None:
    if _CORS_MAX_AGE_HEADER not in response.headers:
        return None

    try:
        max_age = int(response.headers[_CORS_MAX_AGE_HEADER].strip())
    except ValueError:
        return None

    if max_age > _CORS_MAX_AGE_EXCESSIVE:
        raise ValidationError(
            "Access-Control-Max-Age exceeds browser cache limits",
            metadata={"max_age": str(max_age)},
        )

    return "Access-Control-Max-Age is within browser cache limits"
