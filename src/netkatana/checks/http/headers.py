from httpx import Response

from netkatana.models import AbstractHttpCheck, Finding, Severity
from netkatana.utils import parse_content_security_policy, parse_strict_transport_security_header

_HSTS_MIN_MAX_AGE = 31_536_000  # one year


class StrictTransportSecurityMissing(AbstractHttpCheck):
    _code = "headers_strict_transport_security_missing"
    _detail = (
        "The `Strict-Transport-Security` header instructs browsers to always use HTTPS for this domain, "
        "refusing plain HTTP connections. Without it, users are vulnerable to protocol downgrade and SSL "
        "stripping attacks. A `max-age` of at least one year (31,536,000 seconds) is widely recommended."
    )

    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" in response.headers:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.PASS,
                    title="Strict-Transport-Security (HSTS) present",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.CRITICAL,
                title="Strict-Transport-Security (HSTS) missing",
                detail=self._detail,
            )
        ]


class StrictTransportSecurityInvalid(AbstractHttpCheck):
    _code = "headers_strict_transport_security_invalid"
    _detail = (
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
                    code=self._code,
                    severity=Severity.CRITICAL,
                    title="Strict-Transport-Security (HSTS) header is malformed",
                    detail=self._detail,
                    metadata={"value": value},
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) header is valid",
                detail=self._detail,
            )
        ]


class StrictTransportSecurityMaxAgeZero(AbstractHttpCheck):
    _code = "headers_strict_transport_security_max_age_zero"
    _detail = (
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
                    code=self._code,
                    severity=Severity.CRITICAL,
                    title="Strict-Transport-Security (HSTS) max-age is zero",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) max-age is non-zero",
                detail=self._detail,
            )
        ]


class StrictTransportSecurityMaxAgeLow(AbstractHttpCheck):
    _code = "headers_strict_transport_security_max_age_low"
    _detail = (
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
                    code=self._code,
                    severity=Severity.WARNING,
                    title="Strict-Transport-Security (HSTS) max-age is less than one year",
                    detail=self._detail,
                    metadata={"max_age": str(parsed.max_age)},
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) max-age meets minimum",
                detail=self._detail,
            )
        ]


class StrictTransportSecurityIncludeSubdomainsMissing(AbstractHttpCheck):
    _code = "headers_strict_transport_security_include_subdomains_missing"
    _detail = (
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
                    code=self._code,
                    severity=Severity.NOTICE,
                    title="Strict-Transport-Security (HSTS) includeSubDomains missing",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) includeSubDomains present",
                detail=self._detail,
            )
        ]


class StrictTransportSecurityPreloadNotEligible(AbstractHttpCheck):
    # TODO: Do not trigger a notice if "preload" directive is not present.
    _code = "headers_strict_transport_security_preload_not_eligible"
    _detail = (
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

        if parsed.max_age < _HSTS_MIN_MAX_AGE or not parsed.include_subdomains:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.NOTICE,
                    title="Strict-Transport-Security (HSTS) does not meet preload requirements",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.PASS,
                title="Strict-Transport-Security (HSTS) meets preload requirements",
                detail=self._detail,
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
    _code = "headers_content_security_policy_missing"
    _detail = "Without CSP, browsers have no restrictions on which resources they load, increasing the risk of XSS and data injection attacks."

    async def check(self, response: Response) -> list[Finding]:
        if _CSP_HEADER in response.headers:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.PASS,
                    title="Content-Security-Policy (CSP) present",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.WARNING,
                title="Content-Security-Policy (CSP) missing",
                detail=self._detail,
            )
        ]


class ContentSecurityPolicyReportOnlyNoEnforce(AbstractHttpCheck):
    _code = "headers_content_security_policy_report_only_no_enforce"
    _detail = (
        "The `Content-Security-Policy-Report-Only` header instructs browsers to report violations to a "
        "reporting endpoint but not block them. Without an accompanying enforcing "
        "`Content-Security-Policy` header, the policy provides no actual protection — attackers can "
        "still inject and execute scripts or load unauthorized resources."
    )

    async def check(self, response: Response) -> list[Finding]:
        if _CSP_HEADER in response.headers:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.PASS,
                    title="Content-Security-Policy (CSP) is enforced",
                    detail=self._detail,
                )
            ]
        if _CSP_REPORT_ONLY_HEADER not in response.headers:
            return []
        return [
            Finding(
                code=self._code,
                severity=Severity.WARNING,
                title="Content-Security-Policy (CSP) is report-only and not enforced",
                detail=self._detail,
            )
        ]


class ContentSecurityPolicyUnsafeInline(AbstractHttpCheck):
    _code = "headers_content_security_policy_unsafe_inline"
    _detail = (
        "The `'unsafe-inline'` keyword in `script-src` (or `default-src` fallback) permits all inline "
        "scripts, including `<script>` blocks, `javascript:` URLs, and event handler attributes such as "
        "`onclick`. This directly negates XSS protection: any injected HTML can execute arbitrary code. "
        "Use nonces (`'nonce-...'`) or hashes (`'sha256-...'`) for specific inline scripts instead — "
        "when present, CSP Level 2+ browsers ignore `'unsafe-inline'`."
    )

    async def check(self, response: Response) -> list[Finding]:
        if _CSP_HEADER not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[_CSP_HEADER])
        effective = _csp_effective_sources(directives, "script-src")

        if effective is None:
            return []

        if "'unsafe-inline'" not in effective:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.PASS,
                    title="Content-Security-Policy (CSP) script-src does not contain 'unsafe-inline'",
                    detail=self._detail,
                )
            ]

        if _neutralizes_unsafe_inline(effective):
            return [
                Finding(
                    code=self._code,
                    severity=Severity.PASS,
                    title="Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.CRITICAL,
                title="Content-Security-Policy (CSP) script-src contains 'unsafe-inline'",
                detail=self._detail,
            )
        ]


class ContentSecurityPolicyUnsafeEval(AbstractHttpCheck):
    _code = "headers_content_security_policy_unsafe_eval"
    _detail = (
        "The `'unsafe-eval'` keyword in `script-src` (or `default-src` fallback) permits `eval()`, "
        "`new Function(string)`, `setTimeout(string)`, and `setInterval(string)`. These functions "
        "execute arbitrary code from strings, so an attacker who controls any string in the page can "
        "achieve JavaScript execution. Remove `'unsafe-eval'` and refactor code to avoid dynamic "
        "code evaluation."
    )

    async def check(self, response: Response) -> list[Finding]:
        if _CSP_HEADER not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[_CSP_HEADER])
        effective = _csp_effective_sources(directives, "script-src")

        if effective is None:
            return []

        if "'unsafe-eval'" in effective:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.CRITICAL,
                    title="Content-Security-Policy (CSP) script-src contains 'unsafe-eval'",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.PASS,
                title="Content-Security-Policy (CSP) script-src does not contain 'unsafe-eval'",
                detail=self._detail,
            )
        ]


class ContentSecurityPolicyObjectSrcUnsafe(AbstractHttpCheck):
    _code = "headers_content_security_policy_object_src_unsafe"
    _detail = (
        "The `object-src` directive (or `default-src` fallback) controls `<object>` and `<embed>` "
        "elements, which load plugin content such as Flash and Java applets. Plugin content runs "
        "outside the browser's normal security model and has historically been a vector for code "
        "execution. `object-src 'none'` should be set in all modern CSP policies."
    )

    async def check(self, response: Response) -> list[Finding]:
        if _CSP_HEADER not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[_CSP_HEADER])
        effective = _csp_effective_sources(directives, "object-src")

        if effective == ["'none'"]:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.PASS,
                    title="Content-Security-Policy (CSP) object-src is restricted to 'none'",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.WARNING,
                title="Content-Security-Policy (CSP) object-src is not restricted to 'none'",
                detail=self._detail,
            )
        ]


class ContentSecurityPolicyBaseUriMissing(AbstractHttpCheck):
    _code = "headers_content_security_policy_base_uri_missing"
    _detail = (
        "The `base-uri` directive restricts what values the `<base>` element's `href` attribute can "
        "take. Without it, an attacker who can inject `<base href='https://evil.com/'>` redirects all "
        "relative URLs in the page — including relative `<script src>` references — to an "
        "attacker-controlled origin, bypassing `script-src` allowlists. Unlike fetch directives, "
        "`base-uri` does not fall back to `default-src` and must be set explicitly."
    )

    async def check(self, response: Response) -> list[Finding]:
        if _CSP_HEADER not in response.headers:
            return []

        directives = parse_content_security_policy(response.headers[_CSP_HEADER])

        if "base-uri" not in directives:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.WARNING,
                    title="Content-Security-Policy (CSP) base-uri directive is missing",
                    detail=self._detail,
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=Severity.PASS,
                title="Content-Security-Policy (CSP) base-uri directive is present",
                detail=self._detail,
            )
        ]
