import pytest
from httpx import Response

from netkatana.checks.http.headers import (
    ContentSecurityPolicyMissing,
    StrictTransportSecurityIncludeSubdomainsMissing,
    StrictTransportSecurityInvalid,
    StrictTransportSecurityMaxAgeLow,
    StrictTransportSecurityMaxAgeZero,
    StrictTransportSecurityMissing,
    StrictTransportSecurityPreloadNotEligible,
)
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


class TestStrictTransportSecurityInvalid:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await StrictTransportSecurityInvalid().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_valid(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_valid_with_subdomains_and_preload(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains; preload"})
        findings = await StrictTransportSecurityInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_missing_max_age(self):
        response = Response(200, headers={"strict-transport-security": "includeSubDomains"})
        findings = await StrictTransportSecurityInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].code == "headers_strict_transport_security_invalid"

    @pytest.mark.asyncio
    async def test_non_numeric_max_age(self):
        response = Response(200, headers={"strict-transport-security": "max-age=abc"})
        findings = await StrictTransportSecurityInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_any_directive_order(self):
        response = Response(200, headers={"strict-transport-security": "includeSubDomains; max-age=31536000"})
        findings = await StrictTransportSecurityInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_malformed_value(self):
        response = Response(200, headers={"strict-transport-security": "garbage"})
        findings = await StrictTransportSecurityInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].metadata["value"] == "garbage"


class TestStrictTransportSecurityMaxAgeZero:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await StrictTransportSecurityMaxAgeZero().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_header(self):
        response = Response(200, headers={"strict-transport-security": "garbage"})
        findings = await StrictTransportSecurityMaxAgeZero().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_max_age_zero(self):
        response = Response(200, headers={"strict-transport-security": "max-age=0"})
        findings = await StrictTransportSecurityMaxAgeZero().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].code == "headers_strict_transport_security_max_age_zero"

    @pytest.mark.asyncio
    async def test_max_age_nonzero(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMaxAgeZero().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS


class TestStrictTransportSecurityMaxAgeLow:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_header(self):
        response = Response(200, headers={"strict-transport-security": "garbage"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_max_age_zero(self):
        response = Response(200, headers={"strict-transport-security": "max-age=0"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_max_age_low(self):
        response = Response(200, headers={"strict-transport-security": "max-age=86400"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.WARNING
        assert findings[0].code == "headers_strict_transport_security_max_age_low"
        assert findings[0].metadata["max_age"] == "86400"

    @pytest.mark.asyncio
    async def test_max_age_at_minimum(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_max_age_above_minimum(self):
        response = Response(200, headers={"strict-transport-security": "max-age=63072000"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS


class TestStrictTransportSecurityIncludeSubdomainsMissing:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await StrictTransportSecurityIncludeSubdomainsMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_header(self):
        response = Response(200, headers={"strict-transport-security": "garbage"})
        findings = await StrictTransportSecurityIncludeSubdomainsMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_include_subdomains_missing(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityIncludeSubdomainsMissing().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.NOTICE
        assert findings[0].code == "headers_strict_transport_security_include_subdomains_missing"

    @pytest.mark.asyncio
    async def test_include_subdomains_present(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})
        findings = await StrictTransportSecurityIncludeSubdomainsMissing().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS


class TestStrictTransportSecurityPreloadNotEligible:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_header(self):
        response = Response(200, headers={"strict-transport-security": "garbage"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_max_age_too_low(self):
        response = Response(200, headers={"strict-transport-security": "max-age=86400; includeSubDomains"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.NOTICE
        assert findings[0].code == "headers_strict_transport_security_preload_not_eligible"

    @pytest.mark.asyncio
    async def test_include_subdomains_missing(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.NOTICE

    @pytest.mark.asyncio
    async def test_eligible(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_eligible_with_preload(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains; preload"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS


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
