import ipaddress
import re
from urllib.parse import urlparse

from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.types import Validator
from netkatana.utils import parse_content_security_policy

_CSP_HEADER = "content-security-policy"
_CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only"
_CSP_NONCE_SOURCE_RE = re.compile(r"^'nonce-[A-Za-z0-9+/_-]+={0,2}'$")
_CSP_HASH_SOURCE_RE = re.compile(r"^'(sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'$")


def _csp_sources_unrestricted(sources: list[str]) -> bool:
    return "*" in sources or "https:" in sources or "http:" in sources or "wss:" in sources or "ws:" in sources


def _neutralizes_unsafe_inline(sources: list[str]) -> bool:
    return any(
        source.startswith("'nonce-")
        or source.startswith("'sha256-")
        or source.startswith("'sha384-")
        or source.startswith("'sha512-")
        or source == "'strict-dynamic'"
        for source in sources
    )


def _has_invalid_nonce_source(sources: list[str]) -> bool:
    return any(source.startswith("'nonce-") and _CSP_NONCE_SOURCE_RE.fullmatch(source) is None for source in sources)


def _has_invalid_hash_source(sources: list[str]) -> bool:
    return any(source.startswith("'sha") and _CSP_HASH_SOURCE_RE.fullmatch(source) is None for source in sources)


def _effective_sources_for_directive(
    directives: dict[str, list[str]], directive: str, fallback_directives: list[str] | None
) -> list[str] | None:
    effective_sources = directives.get(directive)

    if effective_sources is None and fallback_directives is not None:
        for fallback_directive in fallback_directives:
            if fallback_directive in directives:
                return directives[fallback_directive]

    return effective_sources


def _source_uses_insecure_scheme(source: str) -> bool:
    return source in {"http:", "ws:"} or source.startswith("http://") or source.startswith("ws://")


def _extract_host_from_csp_source(source: str) -> str | None:
    if source.startswith("'") or source.endswith(":"):
        return None

    if "://" in source:
        return urlparse(source).hostname

    return urlparse(f"//{source}").hostname


def _has_ip_source(sources: list[str]) -> bool:
    for source in sources:
        host = _extract_host_from_csp_source(source)
        if host is None:
            continue

        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue

        return True

    return False


async def csp_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        raise ValidationError("Content-Security-Policy (CSP) missing")

    return "Content-Security-Policy (CSP) present"


def _create_duplicated_header_validator(
    *, header: str, success_message: str, error_message: str
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        values = [value.strip() for value in response.headers.get_list(header)]

        if len(values) > 1:
            raise ValidationError(error_message, metadata={"values": ", ".join(values)})

        return success_message

    return validator


csp_duplicated = _create_duplicated_header_validator(
    header=_CSP_HEADER,
    success_message="Content-Security-Policy (CSP) header is not duplicated",
    error_message="Content-Security-Policy (CSP) header is duplicated",
)
csp_report_only_duplicated = _create_duplicated_header_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    success_message="Content-Security-Policy-Report-Only (CSP) header is not duplicated",
    error_message="Content-Security-Policy-Report-Only (CSP) header is duplicated",
)


def _create_missing_directive_validator(
    *,
    header: str,
    directive: str,
    fallback_directives: list[str] | None = None,
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])

        if directive in directives:
            return success_message

        if fallback_directives is not None and any(
            fallback_directive in directives for fallback_directive in fallback_directives
        ):
            return success_message

        raise ValidationError(error_message)

    return validator


csp_base_uri_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="base-uri",
    success_message="Content-Security-Policy (CSP) base-uri is present",
    error_message="Content-Security-Policy (CSP) base-uri is missing",
)
csp_report_only_base_uri_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="base-uri",
    success_message="Content-Security-Policy-Report-Only (CSP) base-uri is present",
    error_message="Content-Security-Policy-Report-Only (CSP) base-uri is missing",
)


def _create_deprecated_directive_validator(
    *, header: str, directive: str, success_message: str, error_message: str
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])

        if directive in directives:
            raise ValidationError(error_message)

        return success_message

    return validator


csp_block_all_mixed_content_deprecated = _create_deprecated_directive_validator(
    header=_CSP_HEADER,
    directive="block-all-mixed-content",
    success_message="Content-Security-Policy (CSP) block-all-mixed-content is absent",
    error_message="Content-Security-Policy (CSP) block-all-mixed-content is deprecated",
)
csp_report_only_block_all_mixed_content_deprecated = _create_deprecated_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="block-all-mixed-content",
    success_message="Content-Security-Policy-Report-Only (CSP) block-all-mixed-content is absent",
    error_message="Content-Security-Policy-Report-Only (CSP) block-all-mixed-content is deprecated",
)

csp_child_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) child-src is present",
    error_message="Content-Security-Policy (CSP) child-src is missing",
)
csp_report_only_child_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) child-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) child-src is missing",
)


def _create_unrestricted_directive_validator(
    *,
    header: str,
    directive: str,
    fallback_directives: list[str] | None = None,
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = _effective_sources_for_directive(directives, directive, fallback_directives)

        if effective_sources is None:
            return None

        if _csp_sources_unrestricted(effective_sources):
            raise ValidationError(error_message)

        return success_message

    return validator


csp_child_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) child-src is restricted",
    error_message="Content-Security-Policy (CSP) child-src is unrestricted",
)
csp_report_only_child_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) child-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) child-src is unrestricted",
)


def _create_nonce_invalid_directive_validator(
    *,
    header: str,
    directive: str,
    fallback_directives: list[str] | None = None,
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = _effective_sources_for_directive(directives, directive, fallback_directives)

        if effective_sources is None:
            return None

        if _has_invalid_nonce_source(effective_sources):
            raise ValidationError(error_message)

        return success_message

    return validator


csp_child_src_nonce_invalid = _create_nonce_invalid_directive_validator(
    header=_CSP_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) child-src nonce sources are valid",
    error_message="Content-Security-Policy (CSP) child-src contains an invalid nonce source",
)
csp_report_only_child_src_nonce_invalid = _create_nonce_invalid_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) child-src nonce sources are valid",
    error_message="Content-Security-Policy-Report-Only (CSP) child-src contains an invalid nonce source",
)


def _create_hash_invalid_directive_validator(
    *,
    header: str,
    directive: str,
    fallback_directives: list[str] | None = None,
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = _effective_sources_for_directive(directives, directive, fallback_directives)

        if effective_sources is None:
            return None

        if _has_invalid_hash_source(effective_sources):
            raise ValidationError(error_message)

        return success_message

    return validator


csp_child_src_hash_invalid = _create_hash_invalid_directive_validator(
    header=_CSP_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) child-src hash sources are valid",
    error_message="Content-Security-Policy (CSP) child-src contains an invalid hash source",
)
csp_report_only_child_src_hash_invalid = _create_hash_invalid_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) child-src hash sources are valid",
    error_message="Content-Security-Policy-Report-Only (CSP) child-src contains an invalid hash source",
)


def _create_source_insecure_scheme_directive_validator(
    *,
    header: str,
    directive: str,
    fallback_directives: list[str] | None = None,
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = _effective_sources_for_directive(directives, directive, fallback_directives)

        if effective_sources is None:
            return None

        if any(_source_uses_insecure_scheme(source) for source in effective_sources):
            raise ValidationError(error_message)

        return success_message

    return validator


csp_child_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) child-src sources do not use insecure schemes",
    error_message="Content-Security-Policy (CSP) child-src contains an insecure scheme source",
)
csp_report_only_child_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) child-src sources do not use insecure schemes",
    error_message="Content-Security-Policy-Report-Only (CSP) child-src contains an insecure scheme source",
)


def _create_source_ip_directive_validator(
    *,
    header: str,
    directive: str,
    fallback_directives: list[str] | None = None,
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = _effective_sources_for_directive(directives, directive, fallback_directives)

        if effective_sources is None:
            return None

        if _has_ip_source(effective_sources):
            raise ValidationError(error_message)

        return success_message

    return validator


csp_child_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) child-src sources do not use IP addresses",
    error_message="Content-Security-Policy (CSP) child-src contains an IP source",
)
csp_report_only_child_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) child-src sources do not use IP addresses",
    error_message="Content-Security-Policy-Report-Only (CSP) child-src contains an IP source",
)

csp_font_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) font-src is present",
    error_message="Content-Security-Policy (CSP) font-src is missing",
)
csp_report_only_font_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) font-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) font-src is missing",
)
csp_font_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) font-src is restricted",
    error_message="Content-Security-Policy (CSP) font-src is unrestricted",
)
csp_report_only_font_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) font-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) font-src is unrestricted",
)
csp_font_src_nonce_invalid = _create_nonce_invalid_directive_validator(
    header=_CSP_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) font-src nonce sources are valid",
    error_message="Content-Security-Policy (CSP) font-src contains an invalid nonce source",
)
csp_report_only_font_src_nonce_invalid = _create_nonce_invalid_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) font-src nonce sources are valid",
    error_message="Content-Security-Policy-Report-Only (CSP) font-src contains an invalid nonce source",
)
csp_font_src_hash_invalid = _create_hash_invalid_directive_validator(
    header=_CSP_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) font-src hash sources are valid",
    error_message="Content-Security-Policy (CSP) font-src contains an invalid hash source",
)
csp_report_only_font_src_hash_invalid = _create_hash_invalid_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) font-src hash sources are valid",
    error_message="Content-Security-Policy-Report-Only (CSP) font-src contains an invalid hash source",
)
csp_font_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) font-src sources do not use insecure schemes",
    error_message="Content-Security-Policy (CSP) font-src contains an insecure scheme source",
)
csp_report_only_font_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) font-src sources do not use insecure schemes",
    error_message="Content-Security-Policy-Report-Only (CSP) font-src contains an insecure scheme source",
)
csp_font_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) font-src sources do not use IP addresses",
    error_message="Content-Security-Policy (CSP) font-src contains an IP source",
)
csp_report_only_font_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="font-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) font-src sources do not use IP addresses",
    error_message="Content-Security-Policy-Report-Only (CSP) font-src contains an IP source",
)
csp_form_action_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy (CSP) form-action is present",
    error_message="Content-Security-Policy (CSP) form-action is missing",
)
csp_report_only_form_action_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy-Report-Only (CSP) form-action is present",
    error_message="Content-Security-Policy-Report-Only (CSP) form-action is missing",
)
csp_form_action_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy (CSP) form-action is restricted",
    error_message="Content-Security-Policy (CSP) form-action is unrestricted",
)
csp_report_only_form_action_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy-Report-Only (CSP) form-action is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) form-action is unrestricted",
)
csp_form_action_nonce_invalid = _create_nonce_invalid_directive_validator(
    header=_CSP_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy (CSP) form-action nonce sources are valid",
    error_message="Content-Security-Policy (CSP) form-action contains an invalid nonce source",
)
csp_report_only_form_action_nonce_invalid = _create_nonce_invalid_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy-Report-Only (CSP) form-action nonce sources are valid",
    error_message="Content-Security-Policy-Report-Only (CSP) form-action contains an invalid nonce source",
)
csp_form_action_hash_invalid = _create_hash_invalid_directive_validator(
    header=_CSP_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy (CSP) form-action hash sources are valid",
    error_message="Content-Security-Policy (CSP) form-action contains an invalid hash source",
)
csp_report_only_form_action_hash_invalid = _create_hash_invalid_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy-Report-Only (CSP) form-action hash sources are valid",
    error_message="Content-Security-Policy-Report-Only (CSP) form-action contains an invalid hash source",
)
csp_form_action_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy (CSP) form-action sources do not use insecure schemes",
    error_message="Content-Security-Policy (CSP) form-action contains an insecure scheme source",
)
csp_report_only_form_action_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy-Report-Only (CSP) form-action sources do not use insecure schemes",
    error_message="Content-Security-Policy-Report-Only (CSP) form-action contains an insecure scheme source",
)
csp_form_action_source_ip = _create_source_ip_directive_validator(
    header=_CSP_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy (CSP) form-action sources do not use IP addresses",
    error_message="Content-Security-Policy (CSP) form-action contains an IP source",
)
csp_report_only_form_action_source_ip = _create_source_ip_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="form-action",
    success_message="Content-Security-Policy-Report-Only (CSP) form-action sources do not use IP addresses",
    error_message="Content-Security-Policy-Report-Only (CSP) form-action contains an IP source",
)


def _create_token_absent_directive_validator(
    *,
    header: str,
    directive: str,
    token: str,
    fallback_directives: list[str] | None = None,
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = _effective_sources_for_directive(directives, directive, fallback_directives)

        if effective_sources is None:
            return None

        if token in effective_sources:
            raise ValidationError(error_message)

        return success_message

    return validator


def _create_unsafe_inline_directive_validator(
    *,
    header: str,
    directive: str,
    fallback_directives: list[str] | None = None,
    absent_message: str,
    neutralized_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = _effective_sources_for_directive(directives, directive, fallback_directives)

        if effective_sources is None:
            return None

        if "'unsafe-inline'" not in effective_sources:
            return absent_message

        if _neutralizes_unsafe_inline(effective_sources):
            return neutralized_message

        raise ValidationError(error_message)

    return validator


def _create_exact_sources_directive_validator(
    *,
    header: str,
    directive: str,
    expected_sources: list[str],
    fallback_directives: list[str] | None = None,
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = _effective_sources_for_directive(directives, directive, fallback_directives)

        if effective_sources == expected_sources:
            return success_message

        raise ValidationError(error_message)

    return validator


def _create_allowed_sources_directive_validator(
    *,
    header: str,
    directive: str,
    allowed_sources: list[list[str]],
    success_message: str,
    error_message: str,
) -> Validator[Response]:
    async def validator(response: Response) -> str | None:
        if header not in response.headers:
            return None

        directives = parse_content_security_policy(response.headers[header])
        effective_sources = directives.get(directive)

        if effective_sources in allowed_sources:
            return success_message

        raise ValidationError(error_message)

    return validator


csp_unsafe_inline = _create_unsafe_inline_directive_validator(
    header=_CSP_HEADER,
    directive="script-src",
    fallback_directives=["default-src"],
    absent_message="Content-Security-Policy (CSP) script-src does not contain 'unsafe-inline'",
    neutralized_message="Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash",
    error_message="Content-Security-Policy (CSP) script-src contains 'unsafe-inline'",
)
csp_report_only_unsafe_inline = _create_unsafe_inline_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="script-src",
    fallback_directives=["default-src"],
    absent_message="Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-inline'",
    neutralized_message="Content-Security-Policy-Report-Only (CSP) 'unsafe-inline' is neutralized by nonce or hash",
    error_message="Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-inline'",
)
csp_unsafe_eval = _create_token_absent_directive_validator(
    header=_CSP_HEADER,
    directive="script-src",
    token="'unsafe-eval'",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) script-src does not contain 'unsafe-eval'",
    error_message="Content-Security-Policy (CSP) script-src contains 'unsafe-eval'",
)
csp_report_only_unsafe_eval = _create_token_absent_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="script-src",
    token="'unsafe-eval'",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-eval'",
    error_message="Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-eval'",
)
csp_object_src_unsafe = _create_exact_sources_directive_validator(
    header=_CSP_HEADER,
    directive="object-src",
    expected_sources=["'none'"],
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) object-src is restricted to 'none'",
    error_message="Content-Security-Policy (CSP) object-src is not restricted to 'none'",
)
csp_report_only_object_src_unsafe = _create_exact_sources_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="object-src",
    expected_sources=["'none'"],
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) object-src is restricted to 'none'",
    error_message="Content-Security-Policy-Report-Only (CSP) object-src is not restricted to 'none'",
)
csp_frame_ancestors_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="frame-ancestors",
    success_message="Content-Security-Policy (CSP) frame-ancestors is present",
    error_message="Content-Security-Policy (CSP) frame-ancestors is missing",
)
csp_report_only_frame_ancestors_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="frame-ancestors",
    success_message="Content-Security-Policy-Report-Only (CSP) frame-ancestors is present",
    error_message="Content-Security-Policy-Report-Only (CSP) frame-ancestors is missing",
)
csp_frame_ancestors_unsafe = _create_allowed_sources_directive_validator(
    header=_CSP_HEADER,
    directive="frame-ancestors",
    allowed_sources=[["'none'"], ["'self'"]],
    success_message="Content-Security-Policy (CSP) frame-ancestors is restricted to 'none' or 'self'",
    error_message="Content-Security-Policy (CSP) frame-ancestors allows origins beyond 'none' or 'self'",
)
csp_report_only_frame_ancestors_unsafe = _create_allowed_sources_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="frame-ancestors",
    allowed_sources=[["'none'"], ["'self'"]],
    success_message="Content-Security-Policy-Report-Only (CSP) frame-ancestors is restricted to 'none' or 'self'",
    error_message="Content-Security-Policy-Report-Only (CSP) frame-ancestors allows origins beyond 'none' or 'self'",
)
csp_frame_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="frame-src",
    fallback_directives=["child-src", "default-src"],
    success_message="Content-Security-Policy (CSP) frame-src is present",
    error_message="Content-Security-Policy (CSP) frame-src is missing",
)
csp_report_only_frame_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="frame-src",
    fallback_directives=["child-src", "default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) frame-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) frame-src is missing",
)
csp_frame_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="frame-src",
    fallback_directives=["child-src", "default-src"],
    success_message="Content-Security-Policy (CSP) frame-src is restricted",
    error_message="Content-Security-Policy (CSP) frame-src is unrestricted",
)
csp_report_only_frame_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="frame-src",
    fallback_directives=["child-src", "default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) frame-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) frame-src is unrestricted",
)
csp_frame_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_HEADER,
    directive="frame-src",
    fallback_directives=["child-src", "default-src"],
    success_message="Content-Security-Policy (CSP) frame-src sources do not use insecure schemes",
    error_message="Content-Security-Policy (CSP) frame-src contains an insecure scheme source",
)
csp_report_only_frame_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="frame-src",
    fallback_directives=["child-src", "default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) frame-src sources do not use insecure schemes",
    error_message="Content-Security-Policy-Report-Only (CSP) frame-src contains an insecure scheme source",
)
csp_frame_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_HEADER,
    directive="frame-src",
    fallback_directives=["child-src", "default-src"],
    success_message="Content-Security-Policy (CSP) frame-src sources do not use IP addresses",
    error_message="Content-Security-Policy (CSP) frame-src contains an IP source",
)
csp_report_only_frame_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="frame-src",
    fallback_directives=["child-src", "default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) frame-src sources do not use IP addresses",
    error_message="Content-Security-Policy-Report-Only (CSP) frame-src contains an IP source",
)
csp_script_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="script-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) script-src is present",
    error_message="Content-Security-Policy (CSP) script-src is missing",
)
csp_report_only_script_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="script-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) script-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) script-src is missing",
)
csp_script_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="script-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) script-src is restricted",
    error_message="Content-Security-Policy (CSP) script-src is unrestricted",
)
csp_report_only_script_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="script-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) script-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) script-src is unrestricted",
)
csp_style_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="style-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) style-src is present",
    error_message="Content-Security-Policy (CSP) style-src is missing",
)
csp_report_only_style_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="style-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) style-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) style-src is missing",
)
csp_style_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="style-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) style-src is restricted",
    error_message="Content-Security-Policy (CSP) style-src is unrestricted",
)
csp_report_only_style_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="style-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) style-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) style-src is unrestricted",
)
csp_connect_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="connect-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) connect-src is present",
    error_message="Content-Security-Policy (CSP) connect-src is missing",
)
csp_report_only_connect_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="connect-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) connect-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) connect-src is missing",
)
csp_connect_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="connect-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) connect-src is restricted",
    error_message="Content-Security-Policy (CSP) connect-src is unrestricted",
)
csp_report_only_connect_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="connect-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) connect-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) connect-src is unrestricted",
)
csp_img_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="img-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) img-src is present",
    error_message="Content-Security-Policy (CSP) img-src is missing",
)
csp_report_only_img_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="img-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) img-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) img-src is missing",
)
csp_img_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="img-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) img-src is restricted",
    error_message="Content-Security-Policy (CSP) img-src is unrestricted",
)
csp_report_only_img_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="img-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) img-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) img-src is unrestricted",
)
csp_manifest_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="manifest-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) manifest-src is present",
    error_message="Content-Security-Policy (CSP) manifest-src is missing",
)
csp_report_only_manifest_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="manifest-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) manifest-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) manifest-src is missing",
)
csp_manifest_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="manifest-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) manifest-src is restricted",
    error_message="Content-Security-Policy (CSP) manifest-src is unrestricted",
)
csp_report_only_manifest_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="manifest-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) manifest-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) manifest-src is unrestricted",
)
csp_manifest_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_HEADER,
    directive="manifest-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) manifest-src sources do not use insecure schemes",
    error_message="Content-Security-Policy (CSP) manifest-src contains an insecure scheme source",
)
csp_report_only_manifest_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="manifest-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) manifest-src sources do not use insecure schemes",
    error_message="Content-Security-Policy-Report-Only (CSP) manifest-src contains an insecure scheme source",
)
csp_manifest_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_HEADER,
    directive="manifest-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) manifest-src sources do not use IP addresses",
    error_message="Content-Security-Policy (CSP) manifest-src contains an IP source",
)
csp_report_only_manifest_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="manifest-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) manifest-src sources do not use IP addresses",
    error_message="Content-Security-Policy-Report-Only (CSP) manifest-src contains an IP source",
)
csp_media_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="media-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) media-src is present",
    error_message="Content-Security-Policy (CSP) media-src is missing",
)
csp_report_only_media_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="media-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) media-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) media-src is missing",
)
csp_media_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="media-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) media-src is restricted",
    error_message="Content-Security-Policy (CSP) media-src is unrestricted",
)
csp_report_only_media_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="media-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) media-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) media-src is unrestricted",
)
csp_media_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_HEADER,
    directive="media-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) media-src sources do not use insecure schemes",
    error_message="Content-Security-Policy (CSP) media-src contains an insecure scheme source",
)
csp_report_only_media_src_source_insecure_scheme = _create_source_insecure_scheme_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="media-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) media-src sources do not use insecure schemes",
    error_message="Content-Security-Policy-Report-Only (CSP) media-src contains an insecure scheme source",
)
csp_media_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_HEADER,
    directive="media-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) media-src sources do not use IP addresses",
    error_message="Content-Security-Policy (CSP) media-src contains an IP source",
)
csp_report_only_media_src_source_ip = _create_source_ip_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="media-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) media-src sources do not use IP addresses",
    error_message="Content-Security-Policy-Report-Only (CSP) media-src contains an IP source",
)
csp_worker_src_missing = _create_missing_directive_validator(
    header=_CSP_HEADER,
    directive="worker-src",
    fallback_directives=["child-src", "script-src", "default-src"],
    success_message="Content-Security-Policy (CSP) worker-src is present",
    error_message="Content-Security-Policy (CSP) worker-src is missing",
)
csp_report_only_worker_src_missing = _create_missing_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="worker-src",
    fallback_directives=["child-src", "script-src", "default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) worker-src is present",
    error_message="Content-Security-Policy-Report-Only (CSP) worker-src is missing",
)
csp_worker_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_HEADER,
    directive="worker-src",
    fallback_directives=["child-src", "script-src", "default-src"],
    success_message="Content-Security-Policy (CSP) worker-src is restricted",
    error_message="Content-Security-Policy (CSP) worker-src is unrestricted",
)
csp_report_only_worker_src_unrestricted = _create_unrestricted_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="worker-src",
    fallback_directives=["child-src", "script-src", "default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) worker-src is restricted",
    error_message="Content-Security-Policy-Report-Only (CSP) worker-src is unrestricted",
)
