from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.utils import parse_content_security_policy

_CSP_HEADER = "content-security-policy"
_CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only"


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


def _csp_sources_unrestricted(sources: list[str] | None) -> bool:
    return "*" in sources or "https:" in sources or "http:" in sources


def _neutralizes_unsafe_inline(sources: list[str]) -> bool:
    return any(
        source.startswith("'nonce-")
        or source.startswith("'sha256-")
        or source.startswith("'sha384-")
        or source.startswith("'sha512-")
        or source == "'strict-dynamic'"
        for source in sources
    )


# TODO: Delete
def _header_values(response: Response, header_name: str) -> list[str]:
    return [value.strip() for value in response.headers.get_list(header_name)]


async def csp_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        raise ValidationError("Content-Security-Policy (CSP) missing")

    return "Content-Security-Policy (CSP) present"


async def csp_duplicated(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    values = _header_values(response, _CSP_HEADER)
    if len(values) > 1:
        raise ValidationError(
            "Content-Security-Policy (CSP) header is duplicated",
            metadata={"values": ", ".join(values)},
        )

    return "Content-Security-Policy (CSP) header is not duplicated"


async def csp_read_only_duplicated(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    values = _header_values(response, _CSP_REPORT_ONLY_HEADER)
    if len(values) > 1:
        raise ValidationError(
            "Content-Security-Policy-Report-Only (CSP) header is duplicated",
            metadata={"values": ", ".join(values)},
        )

    return "Content-Security-Policy-Report-Only (CSP) header is not duplicated"


async def csp_base_uri_missing(response: Response) -> str | None:
    if _CSP_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_HEADER])

    if "base-uri" not in directives:
        raise ValidationError("Content-Security-Policy (CSP) base-uri is missing")

    return "Content-Security-Policy (CSP) base-uri is present"


async def csp_read_only_base_uri_missing(response: Response) -> str | None:
    if _CSP_REPORT_ONLY_HEADER not in response.headers:
        return None

    directives = parse_content_security_policy(response.headers[_CSP_REPORT_ONLY_HEADER])

    if "base-uri" not in directives:
        raise ValidationError("Content-Security-Policy-Report-Only (CSP) base-uri is missing")

    return "Content-Security-Policy-Report-Only (CSP) base-uri is present"


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
