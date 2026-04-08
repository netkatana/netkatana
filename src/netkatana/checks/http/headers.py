from abc import abstractmethod
from typing import ClassVar

from httpx import Response

from netkatana.models import AbstractHttpCheck, Finding, Severity
from netkatana.utils import parse_content_security_policy, parse_strict_transport_security_header

_HSTS_MIN_MAX_AGE = 31_536_000  # one year


class StrictTransportSecurityMissing(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_missing"
    _DETAIL: ClassVar[str] = (
        "The 'Strict-Transport-Security' header instructs browsers to always use HTTPS for this domain, preventing protocol downgrade and SSL stripping attacks."
    )

    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" in response.headers:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Strict-Transport-Security (HSTS) present",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.CRITICAL,
                title="Strict-Transport-Security (HSTS) missing",
                detail=self._DETAIL,
            )
        ]


class StrictTransportSecurityInvalid(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_invalid"
    _DETAIL: ClassVar[str] = (
        "The 'Strict-Transport-Security' header requires a valid 'max-age' directive; a malformed header is silently ignored by browsers."
    )

    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" not in response.headers:
            return []

        value = response.headers["strict-transport-security"]

        try:
            parse_strict_transport_security_header(value)
        except ValueError:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.CRITICAL,
                    title="Strict-Transport-Security (HSTS) header is malformed",
                    detail=self._DETAIL,
                    metadata={"value": value},
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) header is valid",
                detail=self._DETAIL,
            )
        ]


class StrictTransportSecurityMaxAgeZero(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_max_age_zero"
    _DETAIL: ClassVar[str] = (
        "'max-age=0' instructs browsers to delete the cached HSTS policy, removing HTTPS enforcement for returning users."
    )

    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" not in response.headers:
            return []

        try:
            parsed = parse_strict_transport_security_header(response.headers["strict-transport-security"])
        except ValueError:
            return []

        if parsed.max_age == 0:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.CRITICAL,
                    title="Strict-Transport-Security (HSTS) max-age is zero",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) max-age is non-zero",
                detail=self._DETAIL,
            )
        ]


class StrictTransportSecurityMaxAgeLow(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_max_age_low"
    _DETAIL: ClassVar[str] = (
        "The 'max-age' directive controls how long browsers enforce HTTPS for this domain; values below one year (31,536,000 s) leave a wider window for downgrade attacks between visits."
    )

    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" not in response.headers:
            return []

        try:
            parsed = parse_strict_transport_security_header(response.headers["strict-transport-security"])
        except ValueError:
            return []

        if parsed.max_age == 0:
            return []

        if parsed.max_age < _HSTS_MIN_MAX_AGE:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.WARNING,
                    title="Strict-Transport-Security (HSTS) max-age is less than one year",
                    detail=self._DETAIL,
                    metadata={"max_age": str(parsed.max_age)},
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) max-age meets minimum",
                detail=self._DETAIL,
            )
        ]


class StrictTransportSecurityIncludeSubdomainsMissing(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_include_subdomains_missing"
    _DETAIL: ClassVar[str] = (
        "The 'includeSubDomains' directive extends HSTS to all subdomains; without it, subdomains are reachable over plain HTTP and parent-domain cookies may be intercepted."
    )

    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" not in response.headers:
            return []

        try:
            parsed = parse_strict_transport_security_header(response.headers["strict-transport-security"])
        except ValueError:
            return []

        if not parsed.include_subdomains:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.NOTICE,
                    title="Strict-Transport-Security (HSTS) includeSubDomains missing",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) includeSubDomains present",
                detail=self._DETAIL,
            )
        ]


class StrictTransportSecurityPreloadNotEligible(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_preload_not_eligible"
    _DETAIL: ClassVar[str] = (
        "The 'preload' directive signals intent to join browser preload lists, which hardcode the HSTS policy before a user's first visit; qualifying requires 'max-age' ≥ 31,536,000 s and 'includeSubDomains'."
    )

    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" not in response.headers:
            return []

        try:
            parsed = parse_strict_transport_security_header(response.headers["strict-transport-security"])
        except ValueError:
            return []

        if not parsed.preload:
            return []

        if parsed.max_age < _HSTS_MIN_MAX_AGE or not parsed.include_subdomains:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.WARNING,
                    title="Strict-Transport-Security (HSTS) does not meet preload requirements",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) meets preload requirements",
                detail=self._DETAIL,
            )
        ]


_CSP_HEADER = "content-security-policy"
_CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only"


def _csp_effective_sources(directives: dict[str, list[str]], directive: str) -> list[str] | None:
    """Return effective source list for `directive`, falling back to default-src. None means unrestricted."""

    if directive in directives:
        return directives[directive]

    return directives.get("default-src")


def _neutralizes_unsafe_inline(sources: list[str]) -> bool:
    """True if a nonce, hash, or strict-dynamic is present — causing CSP Level 2+ browsers to ignore unsafe-inline."""

    return any(
        s.startswith("'nonce-")
        or s.startswith("'sha256-")
        or s.startswith("'sha384-")
        or s.startswith("'sha512-")
        or s == "'strict-dynamic'"
        for s in sources
    )


class ContentSecurityPolicyMissing(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_csp_missing"
    _DETAIL: ClassVar[str] = (
        "The 'Content-Security-Policy' header restricts which resources browsers can load, reducing the risk of XSS and data injection attacks."
    )

    async def check(self, response: Response) -> list[Finding]:
        if _CSP_HEADER in response.headers:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Content-Security-Policy (CSP) present",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.WARNING,
                title="Content-Security-Policy (CSP) missing",
                detail=self._DETAIL,
            )
        ]


class _CspUnsafeInlineCheck(AbstractHttpCheck):
    _DETAIL: ClassVar[str] = (
        "'unsafe-inline' in 'script-src' (or 'default-src') permits all inline scripts; a nonce or hash neutralizes it and restores XSS protection in CSP Level 2+ browsers."
    )

    @property
    @abstractmethod
    def code(self) -> str:
        pass

    @property
    @abstractmethod
    def header(self) -> str:
        pass

    @property
    @abstractmethod
    def title_prefix(self) -> str:
        pass

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])
        effective = _csp_effective_sources(directives, "script-src")

        if effective is None:
            return []

        if "'unsafe-inline'" not in effective:
            return [
                Finding(
                    code=self.code,
                    severity=Severity.PASS,
                    title=f"{self.title_prefix} script-src does not contain 'unsafe-inline'",
                    detail=self._DETAIL,
                )
            ]

        if _neutralizes_unsafe_inline(effective):
            return [
                Finding(
                    code=self.code,
                    severity=Severity.PASS,
                    title=f"{self.title_prefix} 'unsafe-inline' is neutralized by nonce or hash",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.CRITICAL,
                title=f"{self.title_prefix} script-src contains 'unsafe-inline'",
                detail=self._DETAIL,
            )
        ]


class ContentSecurityPolicyUnsafeInline(_CspUnsafeInlineCheck):
    code = "headers_csp_unsafe_inline"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyUnsafeInline(_CspUnsafeInlineCheck):
    code = "headers_csp_report_only_unsafe_inline"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspUnsafeEvalCheck(AbstractHttpCheck):
    _DETAIL: ClassVar[str] = (
        "'unsafe-eval' in 'script-src' (or 'default-src') permits eval(), new Function(string), and similar dynamic code execution from strings."
    )

    @property
    @abstractmethod
    def code(self) -> str:
        pass

    @property
    @abstractmethod
    def header(self) -> str:
        pass

    @property
    @abstractmethod
    def title_prefix(self) -> str:
        pass

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])
        effective = _csp_effective_sources(directives, "script-src")

        if effective is None:
            return []

        if "'unsafe-eval'" in effective:
            return [
                Finding(
                    code=self.code,
                    severity=Severity.CRITICAL,
                    title=f"{self.title_prefix} script-src contains 'unsafe-eval'",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} script-src does not contain 'unsafe-eval'",
                detail=self._DETAIL,
            )
        ]


class ContentSecurityPolicyUnsafeEval(_CspUnsafeEvalCheck):
    code = "headers_csp_unsafe_eval"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyUnsafeEval(_CspUnsafeEvalCheck):
    code = "headers_csp_report_only_unsafe_eval"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspObjectSrcUnsafeCheck(AbstractHttpCheck):
    _DETAIL: ClassVar[str] = (
        "'object-src' (or 'default-src') controls <object> and <embed> elements; plugin content runs outside the browser's normal security model and has historically enabled code execution."
    )

    @property
    @abstractmethod
    def code(self) -> str:
        pass

    @property
    @abstractmethod
    def header(self) -> str:
        pass

    @property
    @abstractmethod
    def title_prefix(self) -> str:
        pass

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])
        effective = _csp_effective_sources(directives, "object-src")

        if effective == ["'none'"]:
            return [
                Finding(
                    code=self.code,
                    severity=Severity.PASS,
                    title=f"{self.title_prefix} object-src is restricted to 'none'",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.WARNING,
                title=f"{self.title_prefix} object-src is not restricted to 'none'",
                detail=self._DETAIL,
            )
        ]


class ContentSecurityPolicyObjectSrcUnsafe(_CspObjectSrcUnsafeCheck):
    code = "headers_csp_object_src_unsafe"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyObjectSrcUnsafe(_CspObjectSrcUnsafeCheck):
    code = "headers_csp_report_only_object_src_unsafe"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspBaseUriMissingCheck(AbstractHttpCheck):
    _DETAIL: ClassVar[str] = (
        "'base-uri' restricts the <base> element's 'href', preventing attackers from redirecting relative resource loads and bypassing 'script-src'; it does not fall back to 'default-src'."
    )

    @property
    @abstractmethod
    def code(self) -> str:
        pass

    @property
    @abstractmethod
    def header(self) -> str:
        pass

    @property
    @abstractmethod
    def title_prefix(self) -> str:
        pass

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])

        if "base-uri" not in directives:
            return [
                Finding(
                    code=self.code,
                    severity=Severity.WARNING,
                    title=f"{self.title_prefix} base-uri directive is missing",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} base-uri directive is present",
                detail=self._DETAIL,
            )
        ]


class ContentSecurityPolicyBaseUriMissing(_CspBaseUriMissingCheck):
    code = "headers_csp_base_uri_missing"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyBaseUriMissing(_CspBaseUriMissingCheck):
    code = "headers_csp_report_only_base_uri_missing"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspFrameAncestorsMissingCheck(AbstractHttpCheck):
    _DETAIL: ClassVar[str] = (
        "'frame-ancestors' controls which origins can embed this page in a frame or iframe, preventing clickjacking; it does not fall back to 'default-src'."
    )

    @property
    @abstractmethod
    def code(self) -> str:
        pass

    @property
    @abstractmethod
    def header(self) -> str:
        pass

    @property
    @abstractmethod
    def title_prefix(self) -> str:
        pass

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])

        if "frame-ancestors" not in directives:
            return [
                Finding(
                    code=self.code,
                    severity=Severity.WARNING,
                    title=f"{self.title_prefix} frame-ancestors directive is missing",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} frame-ancestors directive is present",
                detail=self._DETAIL,
            )
        ]


class ContentSecurityPolicyFrameAncestorsMissing(_CspFrameAncestorsMissingCheck):
    code = "headers_csp_frame_ancestors_missing"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyFrameAncestorsMissing(_CspFrameAncestorsMissingCheck):
    code = "headers_csp_report_only_frame_ancestors_missing"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspFormActionMissingCheck(AbstractHttpCheck):
    _DETAIL: ClassVar[str] = (
        "'form-action' restricts which URLs forms may submit to, preventing data exfiltration via injected forms; it does not fall back to 'default-src'."
    )

    @property
    @abstractmethod
    def code(self) -> str:
        pass

    @property
    @abstractmethod
    def header(self) -> str:
        pass

    @property
    @abstractmethod
    def title_prefix(self) -> str:
        pass

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])

        if "form-action" not in directives:
            return [
                Finding(
                    code=self.code,
                    severity=Severity.WARNING,
                    title=f"{self.title_prefix} form-action directive is missing",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} form-action directive is present",
                detail=self._DETAIL,
            )
        ]


class ContentSecurityPolicyFormActionMissing(_CspFormActionMissingCheck):
    code = "headers_csp_form_action_missing"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyFormActionMissing(_CspFormActionMissingCheck):
    code = "headers_csp_report_only_form_action_missing"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


_CSP_WILDCARD_SOURCES = {"*", "https:", "http:"}


class _CspFetchDirectiveMissingCheck(AbstractHttpCheck):
    @property
    @abstractmethod
    def code(self) -> str:
        pass

    @property
    @abstractmethod
    def header(self) -> str:
        pass

    @property
    @abstractmethod
    def title_prefix(self) -> str:
        pass

    @property
    @abstractmethod
    def directive(self) -> str:
        pass

    @property
    @abstractmethod
    def detail(self) -> str:
        pass

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])
        effective = _csp_effective_sources(directives, self.directive)

        if effective is None:
            return [
                Finding(
                    code=self.code,
                    severity=Severity.CRITICAL,
                    title=f"{self.title_prefix} {self.directive} is unrestricted (no {self.directive} or default-src)",
                    detail=self.detail,
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} {self.directive} is set",
                detail=self.detail,
            )
        ]


class _CspScriptSrcMissingCheck(_CspFetchDirectiveMissingCheck):
    directive = "script-src"
    detail = "'script-src' (falling back to 'default-src') restricts which scripts browsers execute; without either directive, scripts are completely unrestricted."


class ContentSecurityPolicyScriptSrcMissing(_CspScriptSrcMissingCheck):
    code = "headers_csp_script_src_missing"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyScriptSrcMissing(_CspScriptSrcMissingCheck):
    code = "headers_csp_report_only_script_src_missing"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspStyleSrcMissingCheck(_CspFetchDirectiveMissingCheck):
    directive = "style-src"
    detail = "'style-src' (falling back to 'default-src') restricts which stylesheets browsers load; without either directive, CSS injection and data exfiltration via url() probes are possible."


class ContentSecurityPolicyStyleSrcMissing(_CspStyleSrcMissingCheck):
    code = "headers_csp_style_src_missing"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyStyleSrcMissing(_CspStyleSrcMissingCheck):
    code = "headers_csp_report_only_style_src_missing"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspConnectSrcMissingCheck(_CspFetchDirectiveMissingCheck):
    directive = "connect-src"
    detail = "'connect-src' (falling back to 'default-src') restricts fetch, XHR, and WebSocket destinations; without either directive, connections to arbitrary origins are unrestricted."


class ContentSecurityPolicyConnectSrcMissing(_CspConnectSrcMissingCheck):
    code = "headers_csp_connect_src_missing"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyConnectSrcMissing(_CspConnectSrcMissingCheck):
    code = "headers_csp_report_only_connect_src_missing"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspFetchDirectiveUnrestrictedCheck(AbstractHttpCheck):
    @property
    @abstractmethod
    def code(self) -> str:
        pass

    @property
    @abstractmethod
    def header(self) -> str:
        pass

    @property
    @abstractmethod
    def title_prefix(self) -> str:
        pass

    @property
    @abstractmethod
    def directive(self) -> str:
        pass

    @property
    @abstractmethod
    def detail(self) -> str:
        pass

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])
        effective = _csp_effective_sources(directives, self.directive)

        if effective is None:
            return []

        if any(s in _CSP_WILDCARD_SOURCES for s in effective):
            return [
                Finding(
                    code=self.code,
                    severity=Severity.CRITICAL,
                    title=f"{self.title_prefix} {self.directive} contains a wildcard source",
                    detail=self.detail,
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} {self.directive} does not contain a wildcard source",
                detail=self.detail,
            )
        ]


class _CspScriptSrcUnrestrictedCheck(_CspFetchDirectiveUnrestrictedCheck):
    directive = "script-src"
    detail = "A wildcard source (*, 'https:', or 'http:') in 'script-src' (or 'default-src') allows scripts from any origin, making the allowlist pointless."


class ContentSecurityPolicyScriptSrcUnrestricted(_CspScriptSrcUnrestrictedCheck):
    code = "headers_csp_script_src_unrestricted"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyScriptSrcUnrestricted(_CspScriptSrcUnrestrictedCheck):
    code = "headers_csp_report_only_script_src_unrestricted"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspStyleSrcUnrestrictedCheck(_CspFetchDirectiveUnrestrictedCheck):
    directive = "style-src"
    detail = "A wildcard source (*, 'https:', or 'http:') in 'style-src' (or 'default-src') allows stylesheets from any origin, making the allowlist pointless."


class ContentSecurityPolicyStyleSrcUnrestricted(_CspStyleSrcUnrestrictedCheck):
    code = "headers_csp_style_src_unrestricted"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyStyleSrcUnrestricted(_CspStyleSrcUnrestrictedCheck):
    code = "headers_csp_report_only_style_src_unrestricted"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


class _CspConnectSrcUnrestrictedCheck(_CspFetchDirectiveUnrestrictedCheck):
    directive = "connect-src"
    detail = "A wildcard source (*, 'https:', or 'http:') in 'connect-src' (or 'default-src') allows fetch, XHR, and WebSocket connections to any origin, making the allowlist pointless."


class ContentSecurityPolicyConnectSrcUnrestricted(_CspConnectSrcUnrestrictedCheck):
    code = "headers_csp_connect_src_unrestricted"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyConnectSrcUnrestricted(_CspConnectSrcUnrestrictedCheck):
    code = "headers_csp_report_only_connect_src_unrestricted"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"
