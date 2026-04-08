from abc import abstractmethod
from typing import ClassVar

from httpx import Response

from netkatana.checks.config import get_detail, get_severity
from netkatana.types import AbstractHttpCheck, Finding, Severity
from netkatana.utils import parse_content_security_policy, parse_strict_transport_security_header

_HSTS_MIN_MAX_AGE = 31_536_000  # one year


class StrictTransportSecurityMissing(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_missing"

    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" in response.headers:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Strict-Transport-Security (HSTS) present",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Strict-Transport-Security (HSTS) missing",
                detail=get_detail(self._CODE),
            )
        ]


class StrictTransportSecurityInvalid(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_invalid"

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
                    severity=get_severity(self._CODE),
                    title="Strict-Transport-Security (HSTS) header is malformed",
                    detail=get_detail(self._CODE),
                    metadata={"value": value},
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) header is valid",
                detail=get_detail(self._CODE),
            )
        ]


class StrictTransportSecurityMaxAgeZero(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_max_age_zero"

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
                    severity=get_severity(self._CODE),
                    title="Strict-Transport-Security (HSTS) max-age is zero",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) max-age is non-zero",
                detail=get_detail(self._CODE),
            )
        ]


class StrictTransportSecurityMaxAgeLow(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_max_age_low"

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
                    severity=get_severity(self._CODE),
                    title="Strict-Transport-Security (HSTS) max-age is less than one year",
                    detail=get_detail(self._CODE),
                    metadata={"max_age": str(parsed.max_age)},
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) max-age meets minimum",
                detail=get_detail(self._CODE),
            )
        ]


class StrictTransportSecurityIncludeSubdomainsMissing(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_include_subdomains_missing"

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
                    severity=get_severity(self._CODE),
                    title="Strict-Transport-Security (HSTS) includeSubDomains missing",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) includeSubDomains present",
                detail=get_detail(self._CODE),
            )
        ]


class StrictTransportSecurityPreloadNotEligible(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_preload_not_eligible"

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
                    severity=get_severity(self._CODE),
                    title="Strict-Transport-Security (HSTS) does not meet preload requirements",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) meets preload requirements",
                detail=get_detail(self._CODE),
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

    async def check(self, response: Response) -> list[Finding]:
        if _CSP_HEADER in response.headers:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Content-Security-Policy (CSP) present",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Content-Security-Policy (CSP) missing",
                detail=get_detail(self._CODE),
            )
        ]


class _CspUnsafeInlineCheck(AbstractHttpCheck):
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
                    detail=get_detail(self.code),
                )
            ]

        if _neutralizes_unsafe_inline(effective):
            return [
                Finding(
                    code=self.code,
                    severity=Severity.PASS,
                    title=f"{self.title_prefix} 'unsafe-inline' is neutralized by nonce or hash",
                    detail=get_detail(self.code),
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=get_severity(self.code),
                title=f"{self.title_prefix} script-src contains 'unsafe-inline'",
                detail=get_detail(self.code),
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
                    severity=get_severity(self.code),
                    title=f"{self.title_prefix} script-src contains 'unsafe-eval'",
                    detail=get_detail(self.code),
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} script-src does not contain 'unsafe-eval'",
                detail=get_detail(self.code),
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
                    detail=get_detail(self.code),
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=get_severity(self.code),
                title=f"{self.title_prefix} object-src is not restricted to 'none'",
                detail=get_detail(self.code),
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
                    severity=get_severity(self.code),
                    title=f"{self.title_prefix} base-uri directive is missing",
                    detail=get_detail(self.code),
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} base-uri directive is present",
                detail=get_detail(self.code),
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
                    severity=get_severity(self.code),
                    title=f"{self.title_prefix} frame-ancestors directive is missing",
                    detail=get_detail(self.code),
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} frame-ancestors directive is present",
                detail=get_detail(self.code),
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
                    severity=get_severity(self.code),
                    title=f"{self.title_prefix} form-action directive is missing",
                    detail=get_detail(self.code),
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} form-action directive is present",
                detail=get_detail(self.code),
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

    async def check(self, response: Response) -> list[Finding]:
        if self.header not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[self.header])
        effective = _csp_effective_sources(directives, self.directive)

        if effective is None:
            return [
                Finding(
                    code=self.code,
                    severity=get_severity(self.code),
                    title=f"{self.title_prefix} {self.directive} is unrestricted (no {self.directive} or default-src)",
                    detail=get_detail(self.code),
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} {self.directive} is set",
                detail=get_detail(self.code),
            )
        ]


class _CspScriptSrcMissingCheck(_CspFetchDirectiveMissingCheck):
    directive = "script-src"


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
                    severity=get_severity(self.code),
                    title=f"{self.title_prefix} {self.directive} contains a wildcard source",
                    detail=get_detail(self.code),
                )
            ]

        return [
            Finding(
                code=self.code,
                severity=Severity.PASS,
                title=f"{self.title_prefix} {self.directive} does not contain a wildcard source",
                detail=get_detail(self.code),
            )
        ]


class _CspScriptSrcUnrestrictedCheck(_CspFetchDirectiveUnrestrictedCheck):
    directive = "script-src"


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


class ContentSecurityPolicyConnectSrcUnrestricted(_CspConnectSrcUnrestrictedCheck):
    code = "headers_csp_connect_src_unrestricted"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyConnectSrcUnrestricted(_CspConnectSrcUnrestrictedCheck):
    code = "headers_csp_report_only_connect_src_unrestricted"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"


_CORS_ALLOW_ORIGIN_HEADER = "access-control-allow-origin"
_CORS_ALLOW_CREDENTIALS_HEADER = "access-control-allow-credentials"
_CORS_ALLOW_METHODS_HEADER = "access-control-allow-methods"
_CORS_MAX_AGE_HEADER = "access-control-max-age"
_CORS_MAX_AGE_EXCESSIVE = 86_400
_CORS_UNSAFE_METHODS = {"DELETE", "PUT", "PATCH"}


class AccessControlAllowOriginWildcard(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_cors_allow_origin_wildcard"

    async def check(self, response: Response) -> list[Finding]:
        if _CORS_ALLOW_ORIGIN_HEADER not in response.headers:
            return []

        if response.headers[_CORS_ALLOW_ORIGIN_HEADER].strip() == "*":
            return [
                Finding(
                    code=self._CODE,
                    severity=get_severity(self._CODE),
                    title="Access-Control-Allow-Origin is wildcard (*)",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Access-Control-Allow-Origin is not wildcard",
                detail=get_detail(self._CODE),
            )
        ]


class AccessControlAllowOriginNull(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_cors_allow_origin_null"

    async def check(self, response: Response) -> list[Finding]:
        if _CORS_ALLOW_ORIGIN_HEADER not in response.headers:
            return []

        if response.headers[_CORS_ALLOW_ORIGIN_HEADER].strip() == "null":
            return [
                Finding(
                    code=self._CODE,
                    severity=get_severity(self._CODE),
                    title="Access-Control-Allow-Origin is null",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Access-Control-Allow-Origin is not null",
                detail=get_detail(self._CODE),
            )
        ]


class AccessControlAllowCredentialsWildcard(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_cors_allow_credentials_wildcard"

    async def check(self, response: Response) -> list[Finding]:
        if _CORS_ALLOW_ORIGIN_HEADER not in response.headers:
            return []

        if response.headers[_CORS_ALLOW_ORIGIN_HEADER].strip() != "*":
            return []

        credentials = response.headers.get(_CORS_ALLOW_CREDENTIALS_HEADER, "").strip().lower()
        if credentials == "true":
            return [
                Finding(
                    code=self._CODE,
                    severity=get_severity(self._CODE),
                    title="Access-Control-Allow-Origin is wildcard with credentials enabled",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Access-Control-Allow-Origin wildcard does not enable credentials",
                detail=get_detail(self._CODE),
            )
        ]


class AccessControlAllowCredentialsInvalid(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_cors_allow_credentials_invalid"

    async def check(self, response: Response) -> list[Finding]:
        if _CORS_ALLOW_CREDENTIALS_HEADER not in response.headers:
            return []

        value = response.headers[_CORS_ALLOW_CREDENTIALS_HEADER].strip()
        if value.lower() == "true":
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Access-Control-Allow-Credentials has a valid value",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Access-Control-Allow-Credentials has an invalid value",
                detail=get_detail(self._CODE),
                metadata={"value": value},
            )
        ]


class AccessControlAllowMethodsUnsafe(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_cors_allow_methods_unsafe"

    async def check(self, response: Response) -> list[Finding]:
        if _CORS_ALLOW_METHODS_HEADER not in response.headers:
            return []

        methods = {m.strip().upper() for m in response.headers[_CORS_ALLOW_METHODS_HEADER].split(",")}
        unsafe = methods & _CORS_UNSAFE_METHODS

        if unsafe:
            return [
                Finding(
                    code=self._CODE,
                    severity=get_severity(self._CODE),
                    title="Access-Control-Allow-Methods includes unsafe methods",
                    detail=get_detail(self._CODE),
                    metadata={"methods": ", ".join(sorted(unsafe))},
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Access-Control-Allow-Methods does not include unsafe methods",
                detail=get_detail(self._CODE),
            )
        ]


class AccessControlMaxAgeExcessive(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_cors_max_age_excessive"

    async def check(self, response: Response) -> list[Finding]:
        if _CORS_MAX_AGE_HEADER not in response.headers:
            return []

        try:
            max_age = int(response.headers[_CORS_MAX_AGE_HEADER].strip())
        except ValueError:
            return []

        if max_age > _CORS_MAX_AGE_EXCESSIVE:
            return [
                Finding(
                    code=self._CODE,
                    severity=get_severity(self._CODE),
                    title="Access-Control-Max-Age exceeds browser cache limits",
                    detail=get_detail(self._CODE),
                    metadata={"max_age": str(max_age)},
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=Severity.PASS,
                title="Access-Control-Max-Age is within browser cache limits",
                detail=get_detail(self._CODE),
            )
        ]
