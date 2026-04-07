from httpx import Response

from netkatana.models import AbstractHttpCheck, Finding, Severity


class StrictTransportSecurityMissing(AbstractHttpCheck):
    _code = "headers_strict_transport_security_missing"
    _detail = "Without HSTS, browsers may connect over HTTP and be vulnerable to protocol downgrade and SSL stripping attacks."

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
