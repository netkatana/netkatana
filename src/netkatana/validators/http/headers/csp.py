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


def _csp_effective_sources(directives: dict[str, list[str]], directive: str) -> list[str] | None:
    if directive in directives:
        return directives[directive]

    return directives.get("default-src")


def _csp_effective_worker_sources(directives: dict[str, list[str]]) -> list[str] | None:
    if "worker-src" in directives:
        return directives["worker-src"]

    if "script-src" in directives:
        return directives["script-src"]

    return directives.get("default-src")


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


csp_child_src_insecure_scheme_source = _create_source_insecure_scheme_directive_validator(
    header=_CSP_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) child-src sources do not use insecure schemes",
    error_message="Content-Security-Policy (CSP) child-src contains an insecure scheme source",
)
csp_report_only_child_src_insecure_scheme_source = _create_source_insecure_scheme_directive_validator(
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


csp_child_src_ip_source = _create_source_ip_directive_validator(
    header=_CSP_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy (CSP) child-src sources do not use IP addresses",
    error_message="Content-Security-Policy (CSP) child-src contains an IP source",
)
csp_report_only_child_src_ip_source = _create_source_ip_directive_validator(
    header=_CSP_REPORT_ONLY_HEADER,
    directive="child-src",
    fallback_directives=["default-src"],
    success_message="Content-Security-Policy-Report-Only (CSP) child-src sources do not use IP addresses",
    error_message="Content-Security-Policy-Report-Only (CSP) child-src contains an IP source",
)

# REFACTOR POINT ENDS HERE


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

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy (CSP) script-src is unrestricted")

    return "Content-Security-Policy (CSP) script-src is restricted"


async def csp_ro_script_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "script-src")

    if effective is None:
        return None

    if _csp_sources_unrestricted(effective):
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

    if _csp_sources_unrestricted(effective):
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

    if _csp_sources_unrestricted(effective):
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

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy (CSP) connect-src is unrestricted")

    return "Content-Security-Policy (CSP) connect-src is restricted"


async def csp_img_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "img-src")

    if effective is None:
        return None

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy (CSP) img-src is unrestricted")

    return "Content-Security-Policy (CSP) img-src is restricted"


async def csp_font_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "font-src")

    if effective is None:
        return None

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy (CSP) font-src is unrestricted")

    return "Content-Security-Policy (CSP) font-src is restricted"


async def csp_worker_src_unrestricted(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_worker_sources(directives)

    if effective is None:
        return None

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy (CSP) worker-src is unrestricted")

    return "Content-Security-Policy (CSP) worker-src is restricted"


async def csp_img_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "img-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) img-src is missing")

    return "Content-Security-Policy (CSP) img-src is present"


async def csp_font_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_sources(directives, "font-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) font-src is missing")

    return "Content-Security-Policy (CSP) font-src is present"


async def csp_worker_src_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])
    effective = _csp_effective_worker_sources(directives)

    if effective is None:
        raise ValidationError("Content-Security-Policy (CSP) worker-src is missing")

    return "Content-Security-Policy (CSP) worker-src is present"


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

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) connect-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) connect-src is restricted"


async def csp_ro_img_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "img-src")

    if effective is None:
        return None

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) img-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) img-src is restricted"


async def csp_ro_font_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "font-src")

    if effective is None:
        return None

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) font-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) font-src is restricted"


async def csp_ro_worker_src_unrestricted(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_worker_sources(directives)

    if effective is None:
        return None

    if _csp_sources_unrestricted(effective):
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) worker-src is unrestricted")

    return "Content-Security-Policy-Report-Only (CSP) worker-src is restricted"


async def csp_ro_img_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "img-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) img-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) img-src is present"


async def csp_ro_font_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_sources(directives, "font-src")

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) font-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) font-src is present"


async def csp_ro_worker_src_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])
    effective = _csp_effective_worker_sources(directives)

    if effective is None:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) worker-src is missing")

    return "Content-Security-Policy-Report-Only (CSP) worker-src is present"
