import re

from httpx import Response

from netkatana.models import AbstractHttpCheck, Finding, Severity

_HSTS_RE = re.compile(
    r"^\s*max-age\s*=\s*(?P<max_age>\d+)"
    r"(?:\s*;\s*(?P<include_subdomains>includeSubDomains))?"
    r"(?:\s*;\s*(?P<preload>preload))?"
    r"\s*$",
    re.IGNORECASE,
)

_HSTS_MIN_MAX_AGE = 31_536_000  # one year


def _parse_hsts(value: str) -> tuple[int, bool, bool] | None:
    m = _HSTS_RE.match(value)
    if not m:
        return None
    return (
        int(m.group("max_age")),
        m.group("include_subdomains") is not None,
        m.group("preload") is not None,
    )


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
        parsed = _parse_hsts(value)

        if parsed is None:
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

        parsed = _parse_hsts(response.headers["strict-transport-security"])
        if parsed is None:
            return []

        max_age, _, _ = parsed

        if max_age == 0:
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

        parsed = _parse_hsts(response.headers["strict-transport-security"])
        if parsed is None:
            return []

        max_age, _, _ = parsed
        if max_age == 0:
            return []

        if max_age < _HSTS_MIN_MAX_AGE:
            return [
                Finding(
                    code=self._code,
                    severity=Severity.WARNING,
                    title="Strict-Transport-Security (HSTS) max-age is less than one year",
                    detail=self._detail,
                    metadata={"max_age": str(max_age)},
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

        parsed = _parse_hsts(response.headers["strict-transport-security"])
        if parsed is None:
            return []

        _, include_subdomains, _ = parsed

        if not include_subdomains:
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

        parsed = _parse_hsts(response.headers["strict-transport-security"])
        if parsed is None:
            return []

        max_age, include_subdomains, _ = parsed

        if max_age < _HSTS_MIN_MAX_AGE or not include_subdomains:
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


class ContentSecurityPolicyMissing(AbstractHttpCheck):
    _code = "headers_content_security_policy_missing"
    _detail = "Without CSP, browsers have no restrictions on which resources they load, increasing the risk of XSS and data injection attacks."

    async def check(self, response: Response) -> list[Finding]:
        if "content-security-policy" in response.headers:
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
