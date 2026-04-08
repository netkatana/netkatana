from abc import abstractmethod
from typing import ClassVar

from httpx import Response

from netkatana.models import AbstractHttpCheck, Finding, Severity
from netkatana.utils import parse_content_security_policy, parse_strict_transport_security_header

_HSTS_MIN_MAX_AGE = 31_536_000  # one year


class StrictTransportSecurityMissing(AbstractHttpCheck):
    _CODE: ClassVar[str] = "headers_hsts_missing"
    _DETAIL: ClassVar[str] = (
        "The `Strict-Transport-Security` header instructs browsers to always use HTTPS for this domain, "
        "refusing plain HTTP connections. Without it, users are vulnerable to protocol downgrade and SSL "
        "stripping attacks. A `max-age` of at least one year (31,536,000 seconds) is widely recommended."
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
        "The `Strict-Transport-Security` header requires a valid `max-age` directive with a non-negative "
        "integer value (e.g. `max-age=31536000`). A malformed header is silently ignored by browsers, "
        "providing the same level of protection as if the header were absent entirely."
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
        "A `max-age` of 0 instructs browsers to immediately delete the cached HSTS policy for this domain, "
        "removing enforcement of HTTPS for all future visits. This is only appropriate when intentionally "
        "decommissioning HSTS, as it leaves all returning users unprotected."
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
        "The `max-age` directive controls how long browsers remember to enforce HTTPS for this domain, "
        "in seconds. Short values leave a larger window where returning users may connect over HTTP "
        "between visits. One year (31,536,000 seconds) is the widely recommended minimum; the HSTS "
        "preload list requires at least 18 weeks (10,886,400 seconds)."
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
        "The `includeSubDomains` directive extends the HSTS policy to all subdomains of the current host. "
        "Without it, subdomains are reachable over plain HTTP, which can allow cookies scoped to the parent "
        "domain to be intercepted. Omit this directive only if HTTP access is intentionally permitted on "
        "one or more subdomains."
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
        "Browser preload lists hardcode HSTS policies before a user's first visit, eliminating the window "
        "where an attacker could intercept the initial plain HTTP connection. To qualify, the header must "
        "specify a `max-age` of at least 31,536,000 seconds (one year) and include the `includeSubDomains` "
        "directive. Submission is done via hstspreload.org."
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
        "Without CSP, browsers have no restrictions on which resources they load, increasing the risk of XSS and data injection attacks."
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
        "The `'unsafe-inline'` keyword in `script-src` (or `default-src` fallback) permits all inline "
        "scripts, including `<script>` blocks, `javascript:` URLs, and event handler attributes such as "
        "`onclick`. This directly negates XSS protection: any injected HTML can execute arbitrary code. "
        "Use nonces (`'nonce-...'`) or hashes (`'sha256-...'`) for specific inline scripts instead — "
        "when present, CSP Level 2+ browsers ignore `'unsafe-inline'`."
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
        "The `'unsafe-eval'` keyword in `script-src` (or `default-src` fallback) permits `eval()`, "
        "`new Function(string)`, `setTimeout(string)`, and `setInterval(string)`. These functions "
        "execute arbitrary code from strings, so an attacker who controls any string in the page can "
        "achieve JavaScript execution. Remove `'unsafe-eval'` and refactor code to avoid dynamic "
        "code evaluation."
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
        "The `object-src` directive (or `default-src` fallback) controls `<object>` and `<embed>` "
        "elements, which load plugin content such as Flash and Java applets. Plugin content runs "
        "outside the browser's normal security model and has historically been a vector for code "
        "execution. `object-src 'none'` should be set in all modern CSP policies."
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
        "The `base-uri` directive restricts what values the `<base>` element's `href` attribute can "
        "take. Without it, an attacker who can inject `<base href='https://evil.com/'>` redirects all "
        "relative URLs in the page — including relative `<script src>` references — to an "
        "attacker-controlled origin, bypassing `script-src` allowlists. Unlike fetch directives, "
        "`base-uri` does not fall back to `default-src` and must be set explicitly."
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
        "The `frame-ancestors` directive controls which origins may embed this page in a frame, "
        "iframe, object, or embed element. Without it, any origin can frame the page, enabling "
        "clickjacking attacks. Unlike fetch directives, `frame-ancestors` does not fall back to "
        "`default-src` and must be set explicitly. Use `frame-ancestors 'none'` or "
        "`frame-ancestors 'self'` as appropriate."
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
        "The `form-action` directive restricts the URLs to which forms on the page may submit. "
        "Without it, a form can submit to any origin, which an attacker who can inject HTML "
        "can exploit to exfiltrate data. Unlike fetch directives, `form-action` does not fall "
        "back to `default-src` and must be set explicitly."
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
    detail = (
        "CSP is present but neither `script-src` nor `default-src` is set — scripts are completely "
        "unrestricted, providing no XSS protection despite the header being present."
    )


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
    detail = (
        "CSP is present but neither `style-src` nor `default-src` is set — stylesheets are completely "
        "unrestricted, enabling CSS injection attacks and data exfiltration via `url()` probes."
    )


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
    detail = (
        "CSP is present but neither `connect-src` nor `default-src` is set — fetch, XHR, and "
        "WebSocket connections are completely unrestricted, enabling data exfiltration to arbitrary origins."
    )


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
    detail = (
        "The `script-src` directive (or `default-src` fallback) contains a wildcard source (`*`, "
        "`https:`, or `http:`) — scripts can be loaded from any matching origin, making the "
        "allowlist pointless and providing no XSS protection."
    )


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
    detail = (
        "The `style-src` directive (or `default-src` fallback) contains a wildcard source (`*`, "
        "`https:`, or `http:`) — stylesheets can be loaded from any matching origin, enabling "
        "CSS injection attacks and data exfiltration via `url()` probes."
    )


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
    detail = (
        "The `connect-src` directive (or `default-src` fallback) contains a wildcard source (`*`, "
        "`https:`, or `http:`) — fetch, XHR, and WebSocket connections can target any matching "
        "origin, enabling data exfiltration."
    )


class ContentSecurityPolicyConnectSrcUnrestricted(_CspConnectSrcUnrestrictedCheck):
    code = "headers_csp_connect_src_unrestricted"
    header = _CSP_HEADER
    title_prefix = "Content-Security-Policy (CSP)"


class ContentSecurityPolicyReportOnlyConnectSrcUnrestricted(_CspConnectSrcUnrestrictedCheck):
    code = "headers_csp_report_only_connect_src_unrestricted"
    header = _CSP_REPORT_ONLY_HEADER
    title_prefix = "Content-Security-Policy-Report-Only (CSP)"
