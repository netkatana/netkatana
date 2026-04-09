from httpx import Response

from netkatana.exceptions import ValidationError, ValidationErrors
from netkatana.utils import (
    parse_content_security_policy,
    parse_cross_origin_embedder_policy_header,
    parse_cross_origin_opener_policy_header,
    parse_referrer_policy_header,
    parse_set_cookie_header,
    parse_strict_transport_security_header,
    parse_x_frame_options_header,
)

_HSTS_MIN_MAX_AGE = 31_536_000  # one year
_CSP_HEADER = "content-security-policy"
_CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only"
_CORS_ALLOW_ORIGIN_HEADER = "access-control-allow-origin"
_CORS_ALLOW_CREDENTIALS_HEADER = "access-control-allow-credentials"
_CORS_ALLOW_METHODS_HEADER = "access-control-allow-methods"
_CORS_UNSAFE_METHODS = {"DELETE", "PATCH", "PUT"}
_CORS_MAX_AGE_HEADER = "access-control-max-age"
_CORS_MAX_AGE_EXCESSIVE = 86_400
_CORP_HEADER = "cross-origin-resource-policy"
_CORP_VALID_VALUES = {"same-origin", "same-site", "cross-origin"}
_COEP_HEADER = "cross-origin-embedder-policy"
_COEP_REPORT_ONLY_HEADER = "cross-origin-embedder-policy-report-only"
_COOP_HEADER = "cross-origin-opener-policy"
_COOP_REPORT_ONLY_HEADER = "cross-origin-opener-policy-report-only"
_REFERRER_POLICY_HEADER = "referrer-policy"
_SET_COOKIE_HEADER = "set-cookie"
_X_CONTENT_TYPE_OPTIONS_HEADER = "x-content-type-options"
_X_FRAME_OPTIONS_HEADER = "x-frame-options"


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


def _corp_header_values(response: Response) -> list[str]:
    return [value.strip() for value in response.headers.get_list(_CORP_HEADER)]


async def hsts_missing(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        raise ValidationError("Strict-Transport-Security (HSTS) missing")

    return "Strict-Transport-Security (HSTS) present"


async def hsts_invalid(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        return None

    value = response.headers["strict-transport-security"]

    try:
        parse_strict_transport_security_header(value)
    except ValueError as e:
        raise ValidationError("Strict-Transport-Security (HSTS) header is malformed", metadata={"value": value}) from e

    return "Strict-Transport-Security (HSTS) header is valid"


async def hsts_max_age_zero(response: Response) -> str | None:
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


async def hsts_max_age_low(response: Response) -> str | None:
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


async def hsts_include_subdomains_missing(response: Response) -> str | None:
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


async def hsts_preload_not_eligible(response: Response) -> str | None:
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


async def csp_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        raise ValidationError("Content-Security-Policy (CSP) missing")

    return "Content-Security-Policy (CSP) present"


async def csp_unsafe_inline(response: Response) -> str | None:
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


async def csp_ro_unsafe_inline(response: Response) -> str | None:
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


async def csp_unsafe_eval(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "'unsafe-eval'" in effective:
        raise ValidationError("Content-Security-Policy (CSP) script-src contains 'unsafe-eval'")

    return "Content-Security-Policy (CSP) script-src does not contain 'unsafe-eval'"


async def csp_ro_unsafe_eval(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "'unsafe-eval'" in effective:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-eval'")

    return "Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-eval'"


async def csp_object_src_unsafe(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "object-src")

    if effective == ["'none'"]:
        return "Content-Security-Policy (CSP) object-src is restricted to 'none'"

    raise ValidationError("Content-Security-Policy (CSP) object-src is not restricted to 'none'")


async def csp_ro_object_src_unsafe(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "object-src")

    if effective == ["'none'"]:
        return "Content-Security-Policy-Report-Only (CSP) object-src is restricted to 'none'"

    raise ValidationError("Content-Security-Policy-Report-Only (CSP) object-src is not restricted to 'none'")


async def csp_base_uri_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])

    if "base-uri" not in directives:
        raise ValidationError("Content-Security-Policy (CSP) base-uri is missing")

    return "Content-Security-Policy (CSP) base-uri is present"


async def csp_ro_base_uri_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])

    if "base-uri" not in directives:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) base-uri is missing")

    return "Content-Security-Policy-Report-Only (CSP) base-uri is present"


async def csp_frame_ancestors_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])

    if "frame-ancestors" not in directives:
        raise ValidationError("Content-Security-Policy (CSP) frame-ancestors is missing")

    return "Content-Security-Policy (CSP) frame-ancestors is present"


async def csp_ro_frame_ancestors_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])

    if "frame-ancestors" not in directives:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) frame-ancestors is missing")

    return "Content-Security-Policy-Report-Only (CSP) frame-ancestors is present"


async def csp_form_action_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])

    if "form-action" not in directives:
        raise ValidationError("Content-Security-Policy (CSP) form-action is missing")

    return "Content-Security-Policy (CSP) form-action is present"


async def csp_ro_form_action_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])

    if "form-action" not in directives:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) form-action is missing")

    return "Content-Security-Policy-Report-Only (CSP) form-action is present"


async def csp_script_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) script-src is missing")

    return "Content-Security-Policy (CSP) script-src is present"


async def csp_ro_script_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) script-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) script-src is present"


async def csp_script_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy (CSP) script-src is unrestricted")

    return "Content-Security-Policy (CSP) script-src is restricted"


async def csp_ro_script_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) script-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) script-src is restricted"


async def csp_style_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "style-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) style-src is missing")

    return "Content-Security-Policy (CSP) style-src is present"


async def csp_style_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "style-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy (CSP) style-src is unrestricted")

    return "Content-Security-Policy (CSP) style-src is restricted"


async def csp_ro_style_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "style-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) style-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) style-src is present"


async def csp_ro_style_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "style-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) style-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) style-src is restricted"


async def csp_connect_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "connect-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) connect-src is missing")

    return "Content-Security-Policy (CSP) connect-src is present"


async def csp_connect_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "connect-src")

    if effective is None:
        return None

    if "*" in effective or "https:" in effective or "http:" in effective:
        raise ValidationError("Content-Security-Policy (CSP) connect-src is unrestricted")

    return "Content-Security-Policy (CSP) connect-src is restricted"


async def csp_ro_connect_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "connect-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) connect-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) connect-src is present"


async def csp_ro_connect_src_unrestricted(response: Response) -> str | None:
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


async def corp_missing(response: Response) -> str | None:
    if _CORP_HEADER not in response.headers:
        raise ValidationError("Cross-Origin-Resource-Policy (CORP) missing")

    return "Cross-Origin-Resource-Policy (CORP) present"


async def corp_invalid(response: Response) -> str | None:
    if _CORP_HEADER not in response.headers:
        return None

    values = _corp_header_values(response)
    if len(values) != 1 or values[0] not in _CORP_VALID_VALUES:
        raise ValidationError(
            "Cross-Origin-Resource-Policy (CORP) header is invalid",
            metadata={"value": response.headers[_CORP_HEADER]},
        )

    return "Cross-Origin-Resource-Policy (CORP) header is valid"


async def corp_same_site(response: Response) -> str | None:
    if _CORP_HEADER not in response.headers:
        return None

    values = _corp_header_values(response)
    if len(values) != 1 or values[0] not in _CORP_VALID_VALUES:
        return None

    if values[0] == "same-site":
        raise ValidationError("Cross-Origin-Resource-Policy (CORP) is same-site")

    return "Cross-Origin-Resource-Policy (CORP) is not same-site"


async def corp_cross_origin(response: Response) -> str | None:
    if _CORP_HEADER not in response.headers:
        return None

    values = _corp_header_values(response)
    if len(values) != 1 or values[0] not in _CORP_VALID_VALUES:
        return None

    if values[0] == "cross-origin":
        raise ValidationError("Cross-Origin-Resource-Policy (CORP) is cross-origin")

    return "Cross-Origin-Resource-Policy (CORP) is not cross-origin"


async def coep_missing(response: Response) -> str | None:
    if _COEP_HEADER not in response.headers:
        raise ValidationError("Cross-Origin-Embedder-Policy (COEP) missing")

    return "Cross-Origin-Embedder-Policy (COEP) present"


async def coep_invalid(response: Response) -> str | None:
    if _COEP_HEADER not in response.headers:
        return None

    value = response.headers[_COEP_HEADER]

    try:
        parse_cross_origin_embedder_policy_header(value)
    except ValueError as e:
        raise ValidationError(
            "Cross-Origin-Embedder-Policy (COEP) header is invalid",
            metadata={"value": value},
        ) from e

    return "Cross-Origin-Embedder-Policy (COEP) header is valid"


async def coep_unsafe_none(response: Response) -> str | None:
    if _COEP_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_embedder_policy_header(response.headers[_COEP_HEADER]).policy
    except ValueError:
        return None

    if policy == "unsafe-none":
        raise ValidationError("Cross-Origin-Embedder-Policy (COEP) is unsafe-none")

    return "Cross-Origin-Embedder-Policy (COEP) is not unsafe-none"


async def coep_credentialless(response: Response) -> str | None:
    if _COEP_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_embedder_policy_header(response.headers[_COEP_HEADER]).policy
    except ValueError:
        return None

    if policy == "credentialless":
        raise ValidationError("Cross-Origin-Embedder-Policy (COEP) is credentialless")

    return "Cross-Origin-Embedder-Policy (COEP) is not credentialless"


async def coep_ro_invalid(response: Response) -> str | None:
    if _COEP_REPORT_ONLY_HEADER not in response.headers:
        return None

    value = response.headers[_COEP_REPORT_ONLY_HEADER]

    try:
        parse_cross_origin_embedder_policy_header(value)
    except ValueError as e:
        raise ValidationError(
            "Cross-Origin-Embedder-Policy-Report-Only (COEP) header is invalid",
            metadata={"value": value},
        ) from e

    return "Cross-Origin-Embedder-Policy-Report-Only (COEP) header is valid"


async def coep_ro_unsafe_none(response: Response) -> str | None:
    if _COEP_REPORT_ONLY_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_embedder_policy_header(response.headers[_COEP_REPORT_ONLY_HEADER]).policy
    except ValueError:
        return None

    if policy == "unsafe-none":
        raise ValidationError("Cross-Origin-Embedder-Policy-Report-Only (COEP) is unsafe-none")

    return "Cross-Origin-Embedder-Policy-Report-Only (COEP) is not unsafe-none"


async def coep_ro_credentialless(response: Response) -> str | None:
    if _COEP_REPORT_ONLY_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_embedder_policy_header(response.headers[_COEP_REPORT_ONLY_HEADER]).policy
    except ValueError:
        return None

    if policy == "credentialless":
        raise ValidationError("Cross-Origin-Embedder-Policy-Report-Only (COEP) is credentialless")

    return "Cross-Origin-Embedder-Policy-Report-Only (COEP) is not credentialless"


async def coop_missing(response: Response) -> str | None:
    if _COOP_HEADER not in response.headers:
        raise ValidationError("Cross-Origin-Opener-Policy (COOP) missing")

    return "Cross-Origin-Opener-Policy (COOP) present"


async def coop_invalid(response: Response) -> str | None:
    if _COOP_HEADER not in response.headers:
        return None

    value = response.headers[_COOP_HEADER]

    try:
        parse_cross_origin_opener_policy_header(value)
    except ValueError as e:
        raise ValidationError(
            "Cross-Origin-Opener-Policy (COOP) header is invalid",
            metadata={"value": value},
        ) from e

    return "Cross-Origin-Opener-Policy (COOP) header is valid"


async def coop_unsafe_none(response: Response) -> str | None:
    if _COOP_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_opener_policy_header(response.headers[_COOP_HEADER]).policy
    except ValueError:
        return None

    if policy == "unsafe-none":
        raise ValidationError("Cross-Origin-Opener-Policy (COOP) is unsafe-none")

    return "Cross-Origin-Opener-Policy (COOP) is not unsafe-none"


async def coop_same_origin_allow_popups(response: Response) -> str | None:
    if _COOP_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_opener_policy_header(response.headers[_COOP_HEADER]).policy
    except ValueError:
        return None

    if policy == "same-origin-allow-popups":
        raise ValidationError("Cross-Origin-Opener-Policy (COOP) is same-origin-allow-popups")

    return "Cross-Origin-Opener-Policy (COOP) is not same-origin-allow-popups"


async def coop_noopener_allow_popups(response: Response) -> str | None:
    if _COOP_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_opener_policy_header(response.headers[_COOP_HEADER]).policy
    except ValueError:
        return None

    if policy == "noopener-allow-popups":
        raise ValidationError("Cross-Origin-Opener-Policy (COOP) is noopener-allow-popups")

    return "Cross-Origin-Opener-Policy (COOP) is not noopener-allow-popups"


async def coop_ro_invalid(response: Response) -> str | None:
    if _COOP_REPORT_ONLY_HEADER not in response.headers:
        return None

    value = response.headers[_COOP_REPORT_ONLY_HEADER]

    try:
        parse_cross_origin_opener_policy_header(value)
    except ValueError as e:
        raise ValidationError(
            "Cross-Origin-Opener-Policy-Report-Only (COOP) header is invalid",
            metadata={"value": value},
        ) from e

    return "Cross-Origin-Opener-Policy-Report-Only (COOP) header is valid"


async def coop_ro_unsafe_none(response: Response) -> str | None:
    if _COOP_REPORT_ONLY_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_opener_policy_header(response.headers[_COOP_REPORT_ONLY_HEADER]).policy
    except ValueError:
        return None

    if policy == "unsafe-none":
        raise ValidationError("Cross-Origin-Opener-Policy-Report-Only (COOP) is unsafe-none")

    return "Cross-Origin-Opener-Policy-Report-Only (COOP) is not unsafe-none"


async def coop_ro_same_origin_allow_popups(response: Response) -> str | None:
    if _COOP_REPORT_ONLY_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_opener_policy_header(response.headers[_COOP_REPORT_ONLY_HEADER]).policy
    except ValueError:
        return None

    if policy == "same-origin-allow-popups":
        raise ValidationError("Cross-Origin-Opener-Policy-Report-Only (COOP) is same-origin-allow-popups")

    return "Cross-Origin-Opener-Policy-Report-Only (COOP) is not same-origin-allow-popups"


async def coop_ro_noopener_allow_popups(response: Response) -> str | None:
    if _COOP_REPORT_ONLY_HEADER not in response.headers:
        return None

    try:
        policy = parse_cross_origin_opener_policy_header(response.headers[_COOP_REPORT_ONLY_HEADER]).policy
    except ValueError:
        return None

    if policy == "noopener-allow-popups":
        raise ValidationError("Cross-Origin-Opener-Policy-Report-Only (COOP) is noopener-allow-popups")

    return "Cross-Origin-Opener-Policy-Report-Only (COOP) is not noopener-allow-popups"


async def x_content_type_options_missing(response: Response) -> str | None:
    if _X_CONTENT_TYPE_OPTIONS_HEADER not in response.headers:
        raise ValidationError("X-Content-Type-Options header missing")

    return "X-Content-Type-Options header present"


async def x_content_type_options_invalid(response: Response) -> str | None:
    if _X_CONTENT_TYPE_OPTIONS_HEADER not in response.headers:
        return None

    value = response.headers[_X_CONTENT_TYPE_OPTIONS_HEADER]

    if value.strip().lower() != "nosniff":
        raise ValidationError("X-Content-Type-Options header is invalid", metadata={"value": value})

    return "X-Content-Type-Options header is valid"


async def x_content_type_options_duplicated(response: Response) -> str | None:
    if _X_CONTENT_TYPE_OPTIONS_HEADER not in response.headers:
        return None

    values = [value.strip() for value in response.headers.get_list(_X_CONTENT_TYPE_OPTIONS_HEADER)]
    if len(values) > 1:
        raise ValidationError(
            "X-Content-Type-Options header is duplicated",
            metadata={"values": ", ".join(values)},
        )

    return "X-Content-Type-Options header is not duplicated"


async def referrer_policy_missing(response: Response) -> str | None:
    if _REFERRER_POLICY_HEADER not in response.headers:
        raise ValidationError("Referrer-Policy header missing")

    return "Referrer-Policy header present"


async def referrer_policy_invalid(response: Response) -> str | None:
    if _REFERRER_POLICY_HEADER not in response.headers:
        return None

    value = response.headers[_REFERRER_POLICY_HEADER]

    try:
        parse_referrer_policy_header(value)
    except ValueError as e:
        raise ValidationError("Referrer-Policy header is invalid", metadata={"value": value}) from e

    return "Referrer-Policy header is valid"


async def referrer_policy_unsafe(response: Response) -> str | None:
    if _REFERRER_POLICY_HEADER not in response.headers:
        return None

    try:
        policy = parse_referrer_policy_header(response.headers[_REFERRER_POLICY_HEADER])
    except ValueError:
        return None

    if policy in {"no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "unsafe-url"}:
        raise ValidationError(
            "Referrer-Policy is weaker than 'strict-origin-when-cross-origin'", metadata={"policy": policy}
        )

    return "Referrer-Policy is not weaker than 'strict-origin-when-cross-origin'"


async def x_frame_options_missing(response: Response) -> str | None:
    if _X_FRAME_OPTIONS_HEADER not in response.headers:
        raise ValidationError("X-Frame-Options header missing")

    return "X-Frame-Options header present"


async def x_frame_options_invalid(response: Response) -> str | None:
    if _X_FRAME_OPTIONS_HEADER not in response.headers:
        return None

    value = response.headers[_X_FRAME_OPTIONS_HEADER]

    try:
        parse_x_frame_options_header(value)
    except ValueError as e:
        raise ValidationError("X-Frame-Options header is invalid", metadata={"value": value}) from e

    return "X-Frame-Options header is valid"


async def cookie_secure_missing(response: Response) -> str | None:
    if _SET_COOKIE_HEADER not in response.headers:
        return None

    errors = []
    for value in response.headers.get_list(_SET_COOKIE_HEADER):
        try:
            cookie = parse_set_cookie_header(value)
        except ValueError:
            continue

        if cookie.secure:
            continue

        errors.append(
            ValidationError(
                "Set-Cookie header is missing 'Secure'",
                metadata={"cookie_name": cookie.name},
            )
        )

    if errors:
        raise ValidationErrors(errors)

    return "Set-Cookie headers include 'Secure'"


async def cookie_httponly_missing(response: Response) -> str | None:
    if _SET_COOKIE_HEADER not in response.headers:
        return None

    errors = []
    for value in response.headers.get_list(_SET_COOKIE_HEADER):
        try:
            cookie = parse_set_cookie_header(value)
        except ValueError:
            continue

        if cookie.http_only:
            continue

        errors.append(
            ValidationError(
                "Set-Cookie header is missing 'HttpOnly'",
                metadata={"cookie_name": cookie.name},
            )
        )

    if errors:
        raise ValidationErrors(errors)

    return "Set-Cookie headers include 'HttpOnly'"


async def cookie_samesite_missing(response: Response) -> str | None:
    if _SET_COOKIE_HEADER not in response.headers:
        return None

    errors = []
    for value in response.headers.get_list(_SET_COOKIE_HEADER):
        try:
            cookie = parse_set_cookie_header(value)
        except ValueError:
            continue

        if cookie.same_site is not None:
            continue

        errors.append(
            ValidationError(
                "Set-Cookie header is missing 'SameSite'",
                metadata={"cookie_name": cookie.name},
            )
        )

    if errors:
        raise ValidationErrors(errors)

    return "Set-Cookie headers include 'SameSite'"


async def cookie_prefix_secure_misconfigured(response: Response) -> str | None:
    if _SET_COOKIE_HEADER not in response.headers:
        return None

    errors = []
    for value in response.headers.get_list(_SET_COOKIE_HEADER):
        try:
            cookie = parse_set_cookie_header(value)
        except ValueError:
            continue

        if not cookie.name.startswith("__Secure-"):
            continue

        if cookie.secure:
            continue

        errors.append(
            ValidationError(
                "'__Secure-' cookie is misconfigured",
                metadata={"cookie_name": cookie.name},
            )
        )

    if errors:
        raise ValidationErrors(errors)

    return "'__Secure-' cookies are configured correctly"


async def cookie_prefix_host_misconfigured(response: Response) -> str | None:
    if _SET_COOKIE_HEADER not in response.headers:
        return None

    errors = []
    for value in response.headers.get_list(_SET_COOKIE_HEADER):
        try:
            cookie = parse_set_cookie_header(value)
        except ValueError:
            continue

        if not cookie.name.startswith("__Host-"):
            continue

        if cookie.secure and cookie.domain is None and cookie.path == "/":
            continue

        errors.append(
            ValidationError(
                "'__Host-' cookie is misconfigured",
                metadata={"cookie_name": cookie.name},
            )
        )

    if errors:
        raise ValidationErrors(errors)

    return "'__Host-' cookies are configured correctly"


async def cookie_invalid(response: Response) -> str | None:
    if _SET_COOKIE_HEADER not in response.headers:
        return None

    errors = []
    for value in response.headers.get_list(_SET_COOKIE_HEADER):
        try:
            parse_set_cookie_header(value)
        except ValueError:
            errors.append(ValidationError("Set-Cookie header is invalid", metadata={"value": value}))

    if errors:
        raise ValidationErrors(errors)

    return "Set-Cookie headers are valid"
