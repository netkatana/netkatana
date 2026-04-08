import pytest
from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.validators.http.headers import (
    access_control_allow_origin_null,
    access_control_allow_origin_wildcard,
    content_security_policy_base_uri_missing,
    content_security_policy_connect_src_missing,
    content_security_policy_connect_src_unrestricted,
    content_security_policy_form_action_missing,
    content_security_policy_frame_ancestors_missing,
    content_security_policy_missing,
    content_security_policy_object_src_unsafe,
    content_security_policy_report_only_base_uri_missing,
    content_security_policy_report_only_connect_src_missing,
    content_security_policy_report_only_connect_src_unrestricted,
    content_security_policy_report_only_form_action_missing,
    content_security_policy_report_only_frame_ancestors_missing,
    content_security_policy_report_only_object_src_unsafe,
    content_security_policy_report_only_script_src_missing,
    content_security_policy_report_only_script_src_unrestricted,
    content_security_policy_report_only_style_src_missing,
    content_security_policy_report_only_style_src_unrestricted,
    content_security_policy_report_only_unsafe_eval,
    content_security_policy_report_only_unsafe_inline,
    content_security_policy_script_src_missing,
    content_security_policy_script_src_unrestricted,
    content_security_policy_style_src_missing,
    content_security_policy_style_src_unrestricted,
    content_security_policy_unsafe_eval,
    content_security_policy_unsafe_inline,
    strict_transport_security_include_subdomains_missing,
    strict_transport_security_invalid,
    strict_transport_security_max_age_low,
    strict_transport_security_max_age_zero,
    strict_transport_security_missing,
    strict_transport_security_preload_not_eligible,
)


@pytest.mark.asyncio
async def test_strict_transport_security_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await strict_transport_security_missing(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_strict_transport_security_missing_present():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    message = await strict_transport_security_missing(response)

    assert message == "Strict-Transport-Security (HSTS) present"


@pytest.mark.asyncio
async def test_strict_transport_security_invalid_header_absent():
    response = Response(200)

    message = await strict_transport_security_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_invalid_invalid():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    with pytest.raises(ValidationError) as exc_info:
        await strict_transport_security_invalid(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) header is malformed"
    assert exc_info.value.metadata == {"value": "garbage"}


@pytest.mark.asyncio
async def test_strict_transport_security_invalid_valid():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    message = await strict_transport_security_invalid(response)

    assert message == "Strict-Transport-Security (HSTS) header is valid"


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_zero_header_absent():
    response = Response(200)

    message = await strict_transport_security_max_age_zero(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_zero_invalid_header():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    message = await strict_transport_security_max_age_zero(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_zero_zero():
    response = Response(200, headers={"strict-transport-security": "max-age=0"})

    with pytest.raises(ValidationError) as exc_info:
        await strict_transport_security_max_age_zero(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) max-age is zero"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_zero_non_zero():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    message = await strict_transport_security_max_age_zero(response)

    assert message == "Strict-Transport-Security (HSTS) max-age is non-zero"


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_low_header_absent():
    response = Response(200)

    message = await strict_transport_security_max_age_low(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_low_invalid_header():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    message = await strict_transport_security_max_age_low(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_low_zero():
    response = Response(200, headers={"strict-transport-security": "max-age=0"})

    message = await strict_transport_security_max_age_low(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_low_low():
    response = Response(200, headers={"strict-transport-security": "max-age=86400"})

    with pytest.raises(ValidationError) as exc_info:
        await strict_transport_security_max_age_low(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) max-age is less than one year"
    assert exc_info.value.metadata == {"max_age": "86400"}


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_low_at_minimum():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    message = await strict_transport_security_max_age_low(response)

    assert message == "Strict-Transport-Security (HSTS) max-age meets minimum"


@pytest.mark.asyncio
async def test_strict_transport_security_max_age_low_above_minimum():
    response = Response(200, headers={"strict-transport-security": "max-age=63072000"})

    message = await strict_transport_security_max_age_low(response)

    assert message == "Strict-Transport-Security (HSTS) max-age meets minimum"


@pytest.mark.asyncio
async def test_strict_transport_security_include_subdomains_missing_header_absent():
    response = Response(200)

    message = await strict_transport_security_include_subdomains_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_include_subdomains_missing_invalid_header():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    message = await strict_transport_security_include_subdomains_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_include_subdomains_missing_missing():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    with pytest.raises(ValidationError) as exc_info:
        await strict_transport_security_include_subdomains_missing(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) includeSubDomains missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_strict_transport_security_include_subdomains_missing_present():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})

    message = await strict_transport_security_include_subdomains_missing(response)

    assert message == "Strict-Transport-Security (HSTS) includeSubDomains present"


@pytest.mark.asyncio
async def test_strict_transport_security_preload_not_eligible_header_absent():
    response = Response(200)

    message = await strict_transport_security_preload_not_eligible(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_preload_not_eligible_invalid_header():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    message = await strict_transport_security_preload_not_eligible(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_preload_not_eligible_preload_absent():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})

    message = await strict_transport_security_preload_not_eligible(response)

    assert message is None


@pytest.mark.asyncio
async def test_strict_transport_security_preload_not_eligible_max_age_too_low():
    response = Response(200, headers={"strict-transport-security": "max-age=86400; includeSubDomains; preload"})

    with pytest.raises(ValidationError) as exc_info:
        await strict_transport_security_preload_not_eligible(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) does not meet preload requirements"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_strict_transport_security_preload_not_eligible_include_subdomains_missing():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000; preload"})

    with pytest.raises(ValidationError) as exc_info:
        await strict_transport_security_preload_not_eligible(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) does not meet preload requirements"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_strict_transport_security_preload_not_eligible_eligible():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains; preload"})

    message = await strict_transport_security_preload_not_eligible(response)

    assert message == "Strict-Transport-Security (HSTS) meets preload requirements"


@pytest.mark.asyncio
async def test_content_security_policy_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_missing_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await content_security_policy_missing(response)

    assert message == "Content-Security-Policy (CSP) present"


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_inline_no_csp():
    response = Response(200)

    message = await content_security_policy_unsafe_inline(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_inline_unsafe_inline_in_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self' 'unsafe-inline'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_unsafe_inline(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_inline_unsafe_inline_neutralized_by_nonce():
    response = Response(200, headers={"content-security-policy": "script-src 'nonce-abc123' 'unsafe-inline'"})

    message = await content_security_policy_unsafe_inline(response)

    assert message == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_inline_unsafe_inline_neutralized_by_hash():
    response = Response(200, headers={"content-security-policy": "script-src 'sha256-abc123=' 'unsafe-inline'"})

    message = await content_security_policy_unsafe_inline(response)

    assert message == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_inline_unsafe_inline_neutralized_by_strict_dynamic():
    response = Response(
        200,
        headers={"content-security-policy": "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline'"},
    )

    message = await content_security_policy_unsafe_inline(response)

    assert message == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_inline_via_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_unsafe_inline(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_inline_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await content_security_policy_unsafe_inline(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_inline_clean_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await content_security_policy_unsafe_inline(response)

    assert message == "Content-Security-Policy (CSP) script-src does not contain 'unsafe-inline'"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_inline_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_unsafe_inline(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_inline_unsafe_inline_in_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self' 'unsafe-inline'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_unsafe_inline(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_inline_unsafe_inline_neutralized_by_nonce():
    response = Response(
        200,
        headers={"content-security-policy-report-only": "script-src 'nonce-abc123' 'unsafe-inline'"},
    )

    message = await content_security_policy_report_only_unsafe_inline(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) 'unsafe-inline' is neutralized by nonce or hash"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_inline_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    message = await content_security_policy_report_only_unsafe_inline(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_inline_clean_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    message = await content_security_policy_report_only_unsafe_inline(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-inline'"


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_eval_no_csp():
    response = Response(200)

    message = await content_security_policy_unsafe_eval(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_eval_unsafe_eval_in_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self' 'unsafe-eval'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_unsafe_eval(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-eval'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_eval_via_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-eval'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_unsafe_eval(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-eval'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_eval_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await content_security_policy_unsafe_eval(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_unsafe_eval_clean_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await content_security_policy_unsafe_eval(response)

    assert message == "Content-Security-Policy (CSP) script-src does not contain 'unsafe-eval'"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_eval_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_unsafe_eval(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_eval_unsafe_eval_in_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self' 'unsafe-eval'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_unsafe_eval(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-eval'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_eval_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    message = await content_security_policy_report_only_unsafe_eval(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_unsafe_eval_clean_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    message = await content_security_policy_report_only_unsafe_eval(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-eval'"


@pytest.mark.asyncio
async def test_content_security_policy_object_src_unsafe_no_csp():
    response = Response(200)

    message = await content_security_policy_object_src_unsafe(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_object_src_unsafe_object_src_none():
    response = Response(200, headers={"content-security-policy": "object-src 'none'"})

    message = await content_security_policy_object_src_unsafe(response)

    assert message == "Content-Security-Policy (CSP) object-src is restricted to 'none'"


@pytest.mark.asyncio
async def test_content_security_policy_object_src_unsafe_object_src_self():
    response = Response(200, headers={"content-security-policy": "object-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_object_src_unsafe_no_object_src_default_src_none():
    response = Response(200, headers={"content-security-policy": "default-src 'none'"})

    message = await content_security_policy_object_src_unsafe(response)

    assert message == "Content-Security-Policy (CSP) object-src is restricted to 'none'"


@pytest.mark.asyncio
async def test_content_security_policy_object_src_unsafe_no_object_src_default_src_self():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_object_src_unsafe_no_object_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_object_src_unsafe_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_object_src_unsafe(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_object_src_unsafe_object_src_none():
    response = Response(200, headers={"content-security-policy-report-only": "object-src 'none'"})

    message = await content_security_policy_report_only_object_src_unsafe(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) object-src is restricted to 'none'"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_object_src_unsafe_object_src_self():
    response = Response(200, headers={"content-security-policy-report-only": "object-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_object_src_unsafe_no_object_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_base_uri_missing_no_csp():
    response = Response(200)

    message = await content_security_policy_base_uri_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_base_uri_missing_base_uri_absent():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_base_uri_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) base-uri is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_base_uri_missing_base_uri_none():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; base-uri 'none'"})

    message = await content_security_policy_base_uri_missing(response)

    assert message == "Content-Security-Policy (CSP) base-uri is present"


@pytest.mark.asyncio
async def test_content_security_policy_base_uri_missing_base_uri_self():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; base-uri 'self'"})

    message = await content_security_policy_base_uri_missing(response)

    assert message == "Content-Security-Policy (CSP) base-uri is present"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_base_uri_missing_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_base_uri_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_base_uri_missing_base_uri_absent():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_base_uri_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) base-uri is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_base_uri_missing_base_uri_present():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'; base-uri 'none'"})

    message = await content_security_policy_report_only_base_uri_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) base-uri is present"


@pytest.mark.asyncio
async def test_content_security_policy_frame_ancestors_missing_no_csp():
    response = Response(200)

    message = await content_security_policy_frame_ancestors_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_frame_ancestors_missing_frame_ancestors_absent():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_frame_ancestors_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) frame-ancestors is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_frame_ancestors_missing_frame_ancestors_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; frame-ancestors 'self'"})

    message = await content_security_policy_frame_ancestors_missing(response)

    assert message == "Content-Security-Policy (CSP) frame-ancestors is present"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_frame_ancestors_missing_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_frame_ancestors_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_frame_ancestors_missing_frame_ancestors_absent():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_frame_ancestors_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) frame-ancestors is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_frame_ancestors_missing_frame_ancestors_present():
    response = Response(
        200, headers={"content-security-policy-report-only": "default-src 'self'; frame-ancestors 'self'"}
    )

    message = await content_security_policy_report_only_frame_ancestors_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) frame-ancestors is present"


@pytest.mark.asyncio
async def test_content_security_policy_form_action_missing_no_csp():
    response = Response(200)

    message = await content_security_policy_form_action_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_form_action_missing_form_action_absent():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_form_action_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) form-action is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_form_action_missing_form_action_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; form-action 'self'"})

    message = await content_security_policy_form_action_missing(response)

    assert message == "Content-Security-Policy (CSP) form-action is present"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_form_action_missing_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_form_action_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_form_action_missing_form_action_absent():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_form_action_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) form-action is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_form_action_missing_form_action_present():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'; form-action 'self'"})

    message = await content_security_policy_report_only_form_action_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) form-action is present"


@pytest.mark.asyncio
async def test_content_security_policy_script_src_missing_no_csp():
    response = Response(200)

    message = await content_security_policy_script_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_script_src_missing_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_script_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_script_src_missing_script_src_present():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await content_security_policy_script_src_missing(response)

    assert message == "Content-Security-Policy (CSP) script-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_script_src_missing_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await content_security_policy_script_src_missing(response)

    assert message == "Content-Security-Policy (CSP) script-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_script_src_missing_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_script_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_script_src_missing_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_script_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) script-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_script_src_missing_script_src_present():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    message = await content_security_policy_report_only_script_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) script-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_script_src_unrestricted_no_csp():
    response = Response(200)

    message = await content_security_policy_script_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_script_src_unrestricted_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await content_security_policy_script_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_script_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy": "script-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_script_src_unrestricted_wildcard_https():
    response = Response(200, headers={"content-security-policy": "script-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_script_src_unrestricted_wildcard_http():
    response = Response(200, headers={"content-security-policy": "script-src http:"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_script_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_script_src_unrestricted_clean_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await content_security_policy_script_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) script-src is restricted"


@pytest.mark.asyncio
async def test_content_security_policy_script_src_unrestricted_wildcard_only_in_other_directive():
    response = Response(200, headers={"content-security-policy": "script-src 'self'; img-src *"})

    message = await content_security_policy_script_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) script-src is restricted"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_script_src_unrestricted_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_script_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_script_src_unrestricted_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    message = await content_security_policy_report_only_script_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_script_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy-report-only": "script-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_script_src_unrestricted_clean_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    message = await content_security_policy_report_only_script_src_unrestricted(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) script-src is restricted"


@pytest.mark.asyncio
async def test_content_security_policy_style_src_missing_no_csp():
    response = Response(200)

    message = await content_security_policy_style_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_style_src_missing_no_style_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_style_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_style_src_missing_style_src_present():
    response = Response(200, headers={"content-security-policy": "style-src 'self'"})

    message = await content_security_policy_style_src_missing(response)

    assert message == "Content-Security-Policy (CSP) style-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_style_src_missing_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await content_security_policy_style_src_missing(response)

    assert message == "Content-Security-Policy (CSP) style-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_style_src_unrestricted_no_csp():
    response = Response(200)

    message = await content_security_policy_style_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_style_src_unrestricted_no_style_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await content_security_policy_style_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_style_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy": "style-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_style_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_style_src_unrestricted_wildcard_https():
    response = Response(200, headers={"content-security-policy": "style-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_style_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_style_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_style_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_style_src_unrestricted_clean_style_src():
    response = Response(200, headers={"content-security-policy": "style-src 'self'"})

    message = await content_security_policy_style_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) style-src is restricted"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_style_src_missing_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_style_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_style_src_missing_no_style_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_style_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) style-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_style_src_missing_style_src_present():
    response = Response(200, headers={"content-security-policy-report-only": "style-src 'self'"})

    message = await content_security_policy_report_only_style_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) style-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_style_src_unrestricted_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_style_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_style_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy-report-only": "style-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_style_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) style-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_style_src_unrestricted_clean_style_src():
    response = Response(200, headers={"content-security-policy-report-only": "style-src 'self'"})

    message = await content_security_policy_report_only_style_src_unrestricted(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) style-src is restricted"


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_missing_no_csp():
    response = Response(200)

    message = await content_security_policy_connect_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_missing_no_connect_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_connect_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_missing_connect_src_present():
    response = Response(200, headers={"content-security-policy": "connect-src 'self'"})

    message = await content_security_policy_connect_src_missing(response)

    assert message == "Content-Security-Policy (CSP) connect-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_missing_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await content_security_policy_connect_src_missing(response)

    assert message == "Content-Security-Policy (CSP) connect-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_unrestricted_no_csp():
    response = Response(200)

    message = await content_security_policy_connect_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_unrestricted_no_connect_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await content_security_policy_connect_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy": "connect-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_connect_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_unrestricted_wildcard_https():
    response = Response(200, headers={"content-security-policy": "connect-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_connect_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_connect_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_connect_src_unrestricted_clean_connect_src():
    response = Response(200, headers={"content-security-policy": "connect-src 'self'"})

    message = await content_security_policy_connect_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) connect-src is restricted"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_connect_src_missing_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_connect_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_connect_src_missing_no_connect_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_connect_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) connect-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_connect_src_missing_connect_src_present():
    response = Response(200, headers={"content-security-policy-report-only": "connect-src 'self'"})

    message = await content_security_policy_report_only_connect_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) connect-src is present"


@pytest.mark.asyncio
async def test_content_security_policy_report_only_connect_src_unrestricted_no_header():
    response = Response(200)

    message = await content_security_policy_report_only_connect_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_content_security_policy_report_only_connect_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy-report-only": "connect-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await content_security_policy_report_only_connect_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) connect-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_content_security_policy_report_only_connect_src_unrestricted_clean_connect_src():
    response = Response(200, headers={"content-security-policy-report-only": "connect-src 'self'"})

    message = await content_security_policy_report_only_connect_src_unrestricted(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) connect-src is restricted"


@pytest.mark.asyncio
async def test_access_control_allow_origin_wildcard_header_absent():
    response = Response(200)

    message = await access_control_allow_origin_wildcard(response)

    assert message is None


@pytest.mark.asyncio
async def test_access_control_allow_origin_wildcard_wildcard():
    response = Response(200, headers={"access-control-allow-origin": "*"})

    with pytest.raises(ValidationError) as exc_info:
        await access_control_allow_origin_wildcard(response)

    assert exc_info.value.message == "Access-Control-Allow-Origin is wildcard (*)"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_access_control_allow_origin_wildcard_specific_origin():
    response = Response(200, headers={"access-control-allow-origin": "https://example.com"})

    message = await access_control_allow_origin_wildcard(response)

    assert message == "Access-Control-Allow-Origin is not wildcard"


@pytest.mark.asyncio
async def test_access_control_allow_origin_null_header_absent():
    response = Response(200)

    message = await access_control_allow_origin_null(response)

    assert message is None


@pytest.mark.asyncio
async def test_access_control_allow_origin_null_null():
    response = Response(200, headers={"access-control-allow-origin": "null"})

    with pytest.raises(ValidationError) as exc_info:
        await access_control_allow_origin_null(response)

    assert exc_info.value.message == "Access-Control-Allow-Origin is null"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_access_control_allow_origin_null_specific_origin():
    response = Response(200, headers={"access-control-allow-origin": "https://example.com"})

    message = await access_control_allow_origin_null(response)

    assert message == "Access-Control-Allow-Origin is not null"
