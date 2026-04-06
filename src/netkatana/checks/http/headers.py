from httpx import Response

from netkatana.models import AbstractHttpCheck, Finding, Severity


class StrictTransportSecurityMissing(AbstractHttpCheck):
    async def check(self, response: Response) -> list[Finding]:
        if "strict-transport-security" in response.headers:
            return []

        return [
            Finding(
                code="headers_strict_transport_security_missing",
                severity=Severity.CRITICAL,
                title="Strict-Transport-Security (HSTS) missing",
                detail="Without HSTS, browsers may connect over HTTP and be vulnerable to protocol downgrade and SSL stripping attacks.",
            )
        ]


class ContentSecurityPolicyMissing(AbstractHttpCheck):
    async def check(self, response: Response) -> list[Finding]:
        if "content-security-policy" in response.headers:
            return []

        return [
            Finding(
                code="headers_content_security_policy_missing",
                severity=Severity.WARNING,
                title="Content-Security-Policy (CSP) missing",
                detail="Without CSP, browsers have no restrictions on which resources they load, increasing the risk of XSS and data injection attacks.",
            )
        ]
