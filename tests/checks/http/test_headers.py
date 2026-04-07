import pytest
from httpx import Response

from netkatana.checks.http.headers import (
    ContentSecurityPolicyBaseUriMissing,
    ContentSecurityPolicyMissing,
    ContentSecurityPolicyObjectSrcUnsafe,
    ContentSecurityPolicyReportOnlyBaseUriMissing,
    ContentSecurityPolicyReportOnlyObjectSrcUnsafe,
    ContentSecurityPolicyReportOnlyUnsafeEval,
    ContentSecurityPolicyReportOnlyUnsafeInline,
    ContentSecurityPolicyUnsafeEval,
    ContentSecurityPolicyUnsafeInline,
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
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_present(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_missing"
        assert findings[0].severity == Severity.PASS


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
        assert findings[0].code == "headers_strict_transport_security_invalid"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_invalid(self):
        response = Response(200, headers={"strict-transport-security": "garbage"})
        findings = await StrictTransportSecurityInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_invalid"
        assert findings[0].severity == Severity.CRITICAL


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
        assert findings[0].code == "headers_strict_transport_security_max_age_zero"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_max_age_nonzero(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMaxAgeZero().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_max_age_zero"
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
        assert findings[0].code == "headers_strict_transport_security_max_age_low"
        assert findings[0].severity == Severity.WARNING
        assert findings[0].metadata["max_age"] == "86400"

    @pytest.mark.asyncio
    async def test_max_age_at_minimum(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_max_age_low"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_max_age_above_minimum(self):
        response = Response(200, headers={"strict-transport-security": "max-age=63072000"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_max_age_low"
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
        assert findings[0].code == "headers_strict_transport_security_include_subdomains_missing"
        assert findings[0].severity == Severity.NOTICE

    @pytest.mark.asyncio
    async def test_include_subdomains_present(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})
        findings = await StrictTransportSecurityIncludeSubdomainsMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_include_subdomains_missing"
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
    async def test_preload_absent(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_max_age_too_low(self):
        response = Response(200, headers={"strict-transport-security": "max-age=86400; includeSubDomains; preload"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_preload_not_eligible"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_include_subdomains_missing(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; preload"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_preload_not_eligible"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_eligible(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains; preload"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_strict_transport_security_preload_not_eligible"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyMissing:
    @pytest.mark.asyncio
    async def test_missing(self):
        response = Response(200)
        findings = await ContentSecurityPolicyMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_present(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyUnsafeInline:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_unsafe_inline_in_script_src(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self' 'unsafe-inline'"})
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_inline"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_unsafe_inline_neutralized_by_nonce(self):
        response = Response(
            200,
            headers={"content-security-policy": "script-src 'nonce-abc123' 'unsafe-inline'"},
        )
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_inline"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_unsafe_inline_neutralized_by_hash(self):
        response = Response(
            200,
            headers={"content-security-policy": "script-src 'sha256-abc123=' 'unsafe-inline'"},
        )
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_inline"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_unsafe_inline_neutralized_by_strict_dynamic(self):
        response = Response(
            200,
            headers={"content-security-policy": "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline'"},
        )
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_inline"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_unsafe_inline_via_default_src_fallback(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"})
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_inline"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_script_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "img-src 'self'"})
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_clean_script_src(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self'"})
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_inline"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyUnsafeEval:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyUnsafeEval().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_unsafe_eval_in_script_src(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self' 'unsafe-eval'"})
        findings = await ContentSecurityPolicyUnsafeEval().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_eval"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_unsafe_eval_via_default_src_fallback(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-eval'"})
        findings = await ContentSecurityPolicyUnsafeEval().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_eval"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_script_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "img-src 'self'"})
        findings = await ContentSecurityPolicyUnsafeEval().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_clean_script_src(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self'"})
        findings = await ContentSecurityPolicyUnsafeEval().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_unsafe_eval"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyObjectSrcUnsafe:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_object_src_none(self):
        response = Response(200, headers={"content-security-policy": "object-src 'none'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_object_src_unsafe"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_object_src_self(self):
        response = Response(200, headers={"content-security-policy": "object-src 'self'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_object_src_unsafe"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_no_object_src_default_src_none(self):
        response = Response(200, headers={"content-security-policy": "default-src 'none'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_object_src_unsafe"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_no_object_src_default_src_self(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_object_src_unsafe"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_no_object_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_object_src_unsafe"
        assert findings[0].severity == Severity.WARNING


class TestContentSecurityPolicyBaseUriMissing:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyBaseUriMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_base_uri_absent(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyBaseUriMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_base_uri_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_base_uri_none(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'; base-uri 'none'"})
        findings = await ContentSecurityPolicyBaseUriMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_base_uri_missing"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_base_uri_self(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'; base-uri 'self'"})
        findings = await ContentSecurityPolicyBaseUriMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_base_uri_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyUnsafeInline:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyUnsafeInline().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_unsafe_inline_in_script_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src 'self' 'unsafe-inline'"})
        findings = await ContentSecurityPolicyReportOnlyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_unsafe_inline"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_unsafe_inline_neutralized_by_nonce(self):
        response = Response(
            200,
            headers={"content-security-policy-report-only": "script-src 'nonce-abc123' 'unsafe-inline'"},
        )
        findings = await ContentSecurityPolicyReportOnlyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_unsafe_inline"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_no_script_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyUnsafeInline().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_clean_script_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_unsafe_inline"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyUnsafeEval:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyUnsafeEval().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_unsafe_eval_in_script_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src 'self' 'unsafe-eval'"})
        findings = await ContentSecurityPolicyReportOnlyUnsafeEval().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_unsafe_eval"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_script_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyUnsafeEval().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_clean_script_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyUnsafeEval().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_unsafe_eval"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyObjectSrcUnsafe:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyObjectSrcUnsafe().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_object_src_none(self):
        response = Response(200, headers={"content-security-policy-report-only": "object-src 'none'"})
        findings = await ContentSecurityPolicyReportOnlyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_object_src_unsafe"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_object_src_self(self):
        response = Response(200, headers={"content-security-policy-report-only": "object-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_object_src_unsafe"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_no_object_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_object_src_unsafe"
        assert findings[0].severity == Severity.WARNING


class TestContentSecurityPolicyReportOnlyBaseUriMissing:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyBaseUriMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_base_uri_absent(self):
        response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyBaseUriMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_base_uri_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_base_uri_present(self):
        response = Response(
            200,
            headers={"content-security-policy-report-only": "default-src 'self'; base-uri 'none'"},
        )
        findings = await ContentSecurityPolicyReportOnlyBaseUriMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_content_security_policy_report_only_base_uri_missing"
        assert findings[0].severity == Severity.PASS
