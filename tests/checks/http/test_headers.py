import pytest
from httpx import Response

from netkatana.checks.http.headers import (
    AccessControlAllowCredentialsInvalid,
    AccessControlAllowCredentialsWildcard,
    AccessControlAllowMethodsUnsafe,
    AccessControlAllowOriginNull,
    AccessControlAllowOriginWildcard,
    AccessControlMaxAgeExcessive,
    ContentSecurityPolicyBaseUriMissing,
    ContentSecurityPolicyConnectSrcMissing,
    ContentSecurityPolicyConnectSrcUnrestricted,
    ContentSecurityPolicyFormActionMissing,
    ContentSecurityPolicyFrameAncestorsMissing,
    ContentSecurityPolicyMissing,
    ContentSecurityPolicyObjectSrcUnsafe,
    ContentSecurityPolicyReportOnlyBaseUriMissing,
    ContentSecurityPolicyReportOnlyConnectSrcMissing,
    ContentSecurityPolicyReportOnlyConnectSrcUnrestricted,
    ContentSecurityPolicyReportOnlyFormActionMissing,
    ContentSecurityPolicyReportOnlyFrameAncestorsMissing,
    ContentSecurityPolicyReportOnlyObjectSrcUnsafe,
    ContentSecurityPolicyReportOnlyScriptSrcMissing,
    ContentSecurityPolicyReportOnlyScriptSrcUnrestricted,
    ContentSecurityPolicyReportOnlyStyleSrcMissing,
    ContentSecurityPolicyReportOnlyStyleSrcUnrestricted,
    ContentSecurityPolicyReportOnlyUnsafeEval,
    ContentSecurityPolicyReportOnlyUnsafeInline,
    ContentSecurityPolicyScriptSrcMissing,
    ContentSecurityPolicyScriptSrcUnrestricted,
    ContentSecurityPolicyStyleSrcMissing,
    ContentSecurityPolicyStyleSrcUnrestricted,
    ContentSecurityPolicyUnsafeEval,
    ContentSecurityPolicyUnsafeInline,
    StrictTransportSecurityIncludeSubdomainsMissing,
    StrictTransportSecurityInvalid,
    StrictTransportSecurityMaxAgeLow,
    StrictTransportSecurityMaxAgeZero,
    StrictTransportSecurityMissing,
    StrictTransportSecurityPreloadNotEligible,
)
from netkatana.types import Severity


class TestStrictTransportSecurityMissing:
    @pytest.mark.asyncio
    async def test_missing(self):
        response = Response(200)
        findings = await StrictTransportSecurityMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_missing"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_present(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_missing"
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
        assert findings[0].code == "headers_hsts_invalid"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_invalid(self):
        response = Response(200, headers={"strict-transport-security": "garbage"})
        findings = await StrictTransportSecurityInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_invalid"
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
        assert findings[0].code == "headers_hsts_max_age_zero"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_max_age_nonzero(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMaxAgeZero().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_max_age_zero"
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
        assert findings[0].code == "headers_hsts_max_age_low"
        assert findings[0].severity == Severity.WARNING
        assert findings[0].metadata["max_age"] == "86400"

    @pytest.mark.asyncio
    async def test_max_age_at_minimum(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_max_age_low"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_max_age_above_minimum(self):
        response = Response(200, headers={"strict-transport-security": "max-age=63072000"})
        findings = await StrictTransportSecurityMaxAgeLow().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_max_age_low"
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
        assert findings[0].code == "headers_hsts_include_subdomains_missing"
        assert findings[0].severity == Severity.NOTICE

    @pytest.mark.asyncio
    async def test_include_subdomains_present(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})
        findings = await StrictTransportSecurityIncludeSubdomainsMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_include_subdomains_missing"
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
        assert findings[0].code == "headers_hsts_preload_not_eligible"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_include_subdomains_missing(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; preload"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_preload_not_eligible"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_eligible(self):
        response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains; preload"})
        findings = await StrictTransportSecurityPreloadNotEligible().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_hsts_preload_not_eligible"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyMissing:
    @pytest.mark.asyncio
    async def test_missing(self):
        response = Response(200)
        findings = await ContentSecurityPolicyMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_present(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_missing"
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
        assert findings[0].code == "headers_csp_unsafe_inline"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_unsafe_inline_neutralized_by_nonce(self):
        response = Response(
            200,
            headers={"content-security-policy": "script-src 'nonce-abc123' 'unsafe-inline'"},
        )
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_unsafe_inline"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_unsafe_inline_neutralized_by_hash(self):
        response = Response(
            200,
            headers={"content-security-policy": "script-src 'sha256-abc123=' 'unsafe-inline'"},
        )
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_unsafe_inline"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_unsafe_inline_neutralized_by_strict_dynamic(self):
        response = Response(
            200,
            headers={"content-security-policy": "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline'"},
        )
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_unsafe_inline"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_unsafe_inline_via_default_src_fallback(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"})
        findings = await ContentSecurityPolicyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_unsafe_inline"
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
        assert findings[0].code == "headers_csp_unsafe_inline"
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
        assert findings[0].code == "headers_csp_unsafe_eval"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_unsafe_eval_via_default_src_fallback(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-eval'"})
        findings = await ContentSecurityPolicyUnsafeEval().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_unsafe_eval"
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
        assert findings[0].code == "headers_csp_unsafe_eval"
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
        assert findings[0].code == "headers_csp_object_src_unsafe"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_object_src_self(self):
        response = Response(200, headers={"content-security-policy": "object-src 'self'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_object_src_unsafe"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_no_object_src_default_src_none(self):
        response = Response(200, headers={"content-security-policy": "default-src 'none'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_object_src_unsafe"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_no_object_src_default_src_self(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_object_src_unsafe"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_no_object_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self'"})
        findings = await ContentSecurityPolicyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_object_src_unsafe"
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
        assert findings[0].code == "headers_csp_base_uri_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_base_uri_none(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'; base-uri 'none'"})
        findings = await ContentSecurityPolicyBaseUriMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_base_uri_missing"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_base_uri_self(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'; base-uri 'self'"})
        findings = await ContentSecurityPolicyBaseUriMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_base_uri_missing"
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
        assert findings[0].code == "headers_csp_report_only_unsafe_inline"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_unsafe_inline_neutralized_by_nonce(self):
        response = Response(
            200,
            headers={"content-security-policy-report-only": "script-src 'nonce-abc123' 'unsafe-inline'"},
        )
        findings = await ContentSecurityPolicyReportOnlyUnsafeInline().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_unsafe_inline"
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
        assert findings[0].code == "headers_csp_report_only_unsafe_inline"
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
        assert findings[0].code == "headers_csp_report_only_unsafe_eval"
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
        assert findings[0].code == "headers_csp_report_only_unsafe_eval"
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
        assert findings[0].code == "headers_csp_report_only_object_src_unsafe"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_object_src_self(self):
        response = Response(200, headers={"content-security-policy-report-only": "object-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_object_src_unsafe"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_no_object_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyObjectSrcUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_object_src_unsafe"
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
        assert findings[0].code == "headers_csp_report_only_base_uri_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_base_uri_present(self):
        response = Response(
            200,
            headers={"content-security-policy-report-only": "default-src 'self'; base-uri 'none'"},
        )
        findings = await ContentSecurityPolicyReportOnlyBaseUriMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_base_uri_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyFrameAncestorsMissing:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyFrameAncestorsMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_frame_ancestors_absent(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyFrameAncestorsMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_frame_ancestors_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_frame_ancestors_present(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'; frame-ancestors 'self'"})
        findings = await ContentSecurityPolicyFrameAncestorsMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_frame_ancestors_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyFormActionMissing:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyFormActionMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_form_action_absent(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyFormActionMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_form_action_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_form_action_present(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'; form-action 'self'"})
        findings = await ContentSecurityPolicyFormActionMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_form_action_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyScriptSrcMissing:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyScriptSrcMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_script_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "img-src 'self'"})
        findings = await ContentSecurityPolicyScriptSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_missing"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_script_src_present(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self'"})
        findings = await ContentSecurityPolicyScriptSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_missing"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_default_src_fallback(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyScriptSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyScriptSrcUnrestricted:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyScriptSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_script_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "img-src 'self'"})
        findings = await ContentSecurityPolicyScriptSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_wildcard_star(self):
        response = Response(200, headers={"content-security-policy": "script-src *"})
        findings = await ContentSecurityPolicyScriptSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_wildcard_https(self):
        response = Response(200, headers={"content-security-policy": "script-src https:"})
        findings = await ContentSecurityPolicyScriptSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_wildcard_http(self):
        response = Response(200, headers={"content-security-policy": "script-src http:"})
        findings = await ContentSecurityPolicyScriptSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_wildcard_via_default_src(self):
        response = Response(200, headers={"content-security-policy": "default-src https:"})
        findings = await ContentSecurityPolicyScriptSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_clean_script_src(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self'"})
        findings = await ContentSecurityPolicyScriptSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_unrestricted"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_wildcard_only_in_other_directive(self):
        response = Response(200, headers={"content-security-policy": "script-src 'self'; img-src *"})
        findings = await ContentSecurityPolicyScriptSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_script_src_unrestricted"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyStyleSrcMissing:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyStyleSrcMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_style_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "img-src 'self'"})
        findings = await ContentSecurityPolicyStyleSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_style_src_missing"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_style_src_present(self):
        response = Response(200, headers={"content-security-policy": "style-src 'self'"})
        findings = await ContentSecurityPolicyStyleSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_style_src_missing"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_default_src_fallback(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyStyleSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_style_src_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyStyleSrcUnrestricted:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyStyleSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_style_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "img-src 'self'"})
        findings = await ContentSecurityPolicyStyleSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_wildcard_star(self):
        response = Response(200, headers={"content-security-policy": "style-src *"})
        findings = await ContentSecurityPolicyStyleSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_style_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_wildcard_https(self):
        response = Response(200, headers={"content-security-policy": "style-src https:"})
        findings = await ContentSecurityPolicyStyleSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_style_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_wildcard_via_default_src(self):
        response = Response(200, headers={"content-security-policy": "default-src https:"})
        findings = await ContentSecurityPolicyStyleSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_style_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_clean_style_src(self):
        response = Response(200, headers={"content-security-policy": "style-src 'self'"})
        findings = await ContentSecurityPolicyStyleSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_style_src_unrestricted"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyConnectSrcMissing:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyConnectSrcMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_connect_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "img-src 'self'"})
        findings = await ContentSecurityPolicyConnectSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_connect_src_missing"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_connect_src_present(self):
        response = Response(200, headers={"content-security-policy": "connect-src 'self'"})
        findings = await ContentSecurityPolicyConnectSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_connect_src_missing"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_default_src_fallback(self):
        response = Response(200, headers={"content-security-policy": "default-src 'self'"})
        findings = await ContentSecurityPolicyConnectSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_connect_src_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyConnectSrcUnrestricted:
    @pytest.mark.asyncio
    async def test_no_csp(self):
        response = Response(200)
        findings = await ContentSecurityPolicyConnectSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_connect_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy": "img-src 'self'"})
        findings = await ContentSecurityPolicyConnectSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_wildcard_star(self):
        response = Response(200, headers={"content-security-policy": "connect-src *"})
        findings = await ContentSecurityPolicyConnectSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_connect_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_wildcard_https(self):
        response = Response(200, headers={"content-security-policy": "connect-src https:"})
        findings = await ContentSecurityPolicyConnectSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_connect_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_wildcard_via_default_src(self):
        response = Response(200, headers={"content-security-policy": "default-src https:"})
        findings = await ContentSecurityPolicyConnectSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_connect_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_clean_connect_src(self):
        response = Response(200, headers={"content-security-policy": "connect-src 'self'"})
        findings = await ContentSecurityPolicyConnectSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_connect_src_unrestricted"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyFrameAncestorsMissing:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyFrameAncestorsMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_frame_ancestors_absent(self):
        response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyFrameAncestorsMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_frame_ancestors_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_frame_ancestors_present(self):
        response = Response(
            200,
            headers={"content-security-policy-report-only": "default-src 'self'; frame-ancestors 'self'"},
        )
        findings = await ContentSecurityPolicyReportOnlyFrameAncestorsMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_frame_ancestors_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyFormActionMissing:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyFormActionMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_form_action_absent(self):
        response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyFormActionMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_form_action_missing"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_form_action_present(self):
        response = Response(
            200,
            headers={"content-security-policy-report-only": "default-src 'self'; form-action 'self'"},
        )
        findings = await ContentSecurityPolicyReportOnlyFormActionMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_form_action_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyScriptSrcMissing:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyScriptSrcMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_script_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyScriptSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_script_src_missing"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_script_src_present(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyScriptSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_script_src_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyScriptSrcUnrestricted:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyScriptSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_wildcard_star(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src *"})
        findings = await ContentSecurityPolicyReportOnlyScriptSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_script_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_clean_script_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyScriptSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_script_src_unrestricted"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyStyleSrcMissing:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyStyleSrcMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_style_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyStyleSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_style_src_missing"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_style_src_present(self):
        response = Response(200, headers={"content-security-policy-report-only": "style-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyStyleSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_style_src_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyStyleSrcUnrestricted:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyStyleSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_wildcard_star(self):
        response = Response(200, headers={"content-security-policy-report-only": "style-src *"})
        findings = await ContentSecurityPolicyReportOnlyStyleSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_style_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_clean_style_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "style-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyStyleSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_style_src_unrestricted"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyConnectSrcMissing:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyConnectSrcMissing().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_connect_src_no_default_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyConnectSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_connect_src_missing"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_connect_src_present(self):
        response = Response(200, headers={"content-security-policy-report-only": "connect-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyConnectSrcMissing().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_connect_src_missing"
        assert findings[0].severity == Severity.PASS


class TestContentSecurityPolicyReportOnlyConnectSrcUnrestricted:
    @pytest.mark.asyncio
    async def test_no_header(self):
        response = Response(200)
        findings = await ContentSecurityPolicyReportOnlyConnectSrcUnrestricted().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_wildcard_star(self):
        response = Response(200, headers={"content-security-policy-report-only": "connect-src *"})
        findings = await ContentSecurityPolicyReportOnlyConnectSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_connect_src_unrestricted"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_clean_connect_src(self):
        response = Response(200, headers={"content-security-policy-report-only": "connect-src 'self'"})
        findings = await ContentSecurityPolicyReportOnlyConnectSrcUnrestricted().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_csp_report_only_connect_src_unrestricted"
        assert findings[0].severity == Severity.PASS


class TestAccessControlAllowOriginWildcard:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await AccessControlAllowOriginWildcard().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_wildcard(self):
        response = Response(200, headers={"access-control-allow-origin": "*"})
        findings = await AccessControlAllowOriginWildcard().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_origin_wildcard"
        assert findings[0].severity == Severity.WARNING

    @pytest.mark.asyncio
    async def test_specific_origin(self):
        response = Response(200, headers={"access-control-allow-origin": "https://example.com"})
        findings = await AccessControlAllowOriginWildcard().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_origin_wildcard"
        assert findings[0].severity == Severity.PASS


class TestAccessControlAllowOriginNull:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await AccessControlAllowOriginNull().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_null(self):
        response = Response(200, headers={"access-control-allow-origin": "null"})
        findings = await AccessControlAllowOriginNull().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_origin_null"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_specific_origin(self):
        response = Response(200, headers={"access-control-allow-origin": "https://example.com"})
        findings = await AccessControlAllowOriginNull().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_origin_null"
        assert findings[0].severity == Severity.PASS


class TestAccessControlAllowCredentialsWildcard:
    @pytest.mark.asyncio
    async def test_no_cors_header(self):
        response = Response(200)
        findings = await AccessControlAllowCredentialsWildcard().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_specific_origin_with_credentials(self):
        response = Response(
            200,
            headers={
                "access-control-allow-origin": "https://example.com",
                "access-control-allow-credentials": "true",
            },
        )
        findings = await AccessControlAllowCredentialsWildcard().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_wildcard_without_credentials(self):
        response = Response(200, headers={"access-control-allow-origin": "*"})
        findings = await AccessControlAllowCredentialsWildcard().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_credentials_wildcard"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials(self):
        response = Response(
            200,
            headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
        )
        findings = await AccessControlAllowCredentialsWildcard().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_credentials_wildcard"
        assert findings[0].severity == Severity.CRITICAL


class TestAccessControlAllowCredentialsInvalid:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await AccessControlAllowCredentialsInvalid().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_valid_lowercase(self):
        response = Response(200, headers={"access-control-allow-credentials": "true"})
        findings = await AccessControlAllowCredentialsInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_credentials_invalid"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_valid_uppercase(self):
        response = Response(200, headers={"access-control-allow-credentials": "TRUE"})
        findings = await AccessControlAllowCredentialsInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_credentials_invalid"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_invalid_value(self):
        response = Response(200, headers={"access-control-allow-credentials": "1"})
        findings = await AccessControlAllowCredentialsInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_credentials_invalid"
        assert findings[0].severity == Severity.WARNING
        assert findings[0].metadata == {"value": "1"}

    @pytest.mark.asyncio
    async def test_false_value(self):
        response = Response(200, headers={"access-control-allow-credentials": "false"})
        findings = await AccessControlAllowCredentialsInvalid().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_credentials_invalid"
        assert findings[0].severity == Severity.WARNING


class TestAccessControlAllowMethodsUnsafe:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await AccessControlAllowMethodsUnsafe().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_safe_methods(self):
        response = Response(200, headers={"access-control-allow-methods": "GET, POST, OPTIONS"})
        findings = await AccessControlAllowMethodsUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_methods_unsafe"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_delete(self):
        response = Response(200, headers={"access-control-allow-methods": "GET, DELETE"})
        findings = await AccessControlAllowMethodsUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_methods_unsafe"
        assert findings[0].severity == Severity.NOTICE
        assert findings[0].metadata == {"methods": "DELETE"}

    @pytest.mark.asyncio
    async def test_multiple_unsafe(self):
        response = Response(200, headers={"access-control-allow-methods": "GET, PUT, DELETE, PATCH"})
        findings = await AccessControlAllowMethodsUnsafe().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_allow_methods_unsafe"
        assert findings[0].severity == Severity.NOTICE
        assert findings[0].metadata == {"methods": "DELETE, PATCH, PUT"}


class TestAccessControlMaxAgeExcessive:
    @pytest.mark.asyncio
    async def test_header_absent(self):
        response = Response(200)
        findings = await AccessControlMaxAgeExcessive().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_value(self):
        response = Response(200, headers={"access-control-max-age": "notanumber"})
        findings = await AccessControlMaxAgeExcessive().check(response)

        assert findings == []

    @pytest.mark.asyncio
    async def test_within_limit(self):
        response = Response(200, headers={"access-control-max-age": "7200"})
        findings = await AccessControlMaxAgeExcessive().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_max_age_excessive"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_at_limit(self):
        response = Response(200, headers={"access-control-max-age": "86400"})
        findings = await AccessControlMaxAgeExcessive().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_max_age_excessive"
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_excessive(self):
        response = Response(200, headers={"access-control-max-age": "86401"})
        findings = await AccessControlMaxAgeExcessive().check(response)

        assert len(findings) == 1
        assert findings[0].code == "headers_cors_max_age_excessive"
        assert findings[0].severity == Severity.NOTICE
        assert findings[0].metadata == {"max_age": "86401"}
