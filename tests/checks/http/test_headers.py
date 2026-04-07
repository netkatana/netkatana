import pytest
from httpx import Response

from netkatana.checks.http.headers import ContentSecurityPolicyMissing, StrictTransportSecurityMissing
from netkatana.models import Severity


class TestStrictTransportSecurityMissing:
    @pytest.mark.asyncio
    async def test_missing(self):
        response = Response(200)
        findings = await StrictTransportSecurityMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_missing"

    @pytest.mark.asyncio
    async def test_present(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMissing().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
        assert findings[0].code == "headers_strict_transport_security_missing"


class TestContentSecurityPolicyMissing:
    @pytest.mark.asyncio
    async def test_missing(self):
        response = Response(200)
        findings = await ContentSecurityPolicyMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_missing"

    @pytest.mark.asyncio
    async def test_present(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyMissing().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
        assert findings[0].code == "headers_content_security_policy_missing"
