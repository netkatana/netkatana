import pytest
from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.validators.http.headers import (
    access_control_allow_credentials_invalid,
    access_control_allow_credentials_wildcard,
    access_control_allow_methods_unsafe,
    access_control_allow_origin_null,
    access_control_allow_origin_wildcard,
    access_control_max_age_excessive,
    coep_credentialless,
    coep_invalid,
    coep_missing,
    coep_ro_credentialless,
    coep_ro_invalid,
    coep_ro_unsafe_none,
    coep_unsafe_none,
    coop_invalid,
    coop_missing,
    coop_noopener_allow_popups,
    coop_ro_invalid,
    coop_ro_noopener_allow_popups,
    coop_ro_same_origin_allow_popups,
    coop_ro_unsafe_none,
    coop_same_origin_allow_popups,
    coop_unsafe_none,
    corp_cross_origin,
    corp_invalid,
    corp_missing,
    corp_same_site,
    csp_base_uri_missing,
    csp_connect_src_missing,
    csp_connect_src_unrestricted,
    csp_form_action_missing,
    csp_frame_ancestors_missing,
    csp_missing,
    csp_object_src_unsafe,
    csp_ro_base_uri_missing,
    csp_ro_connect_src_missing,
    csp_ro_connect_src_unrestricted,
    csp_ro_form_action_missing,
    csp_ro_frame_ancestors_missing,
    csp_ro_object_src_unsafe,
    csp_ro_script_src_missing,
    csp_ro_script_src_unrestricted,
    csp_ro_style_src_missing,
    csp_ro_style_src_unrestricted,
    csp_ro_unsafe_eval,
    csp_ro_unsafe_inline,
    csp_script_src_missing,
    csp_script_src_unrestricted,
    csp_style_src_missing,
    csp_style_src_unrestricted,
    csp_unsafe_eval,
    csp_unsafe_inline,
    hsts_include_subdomains_missing,
    hsts_invalid,
    hsts_max_age_low,
    hsts_max_age_zero,
    hsts_missing,
    hsts_preload_not_eligible,
    referrer_policy_invalid,
    referrer_policy_missing,
    referrer_policy_unsafe,
    x_content_type_options_duplicated,
    x_content_type_options_invalid,
    x_content_type_options_missing,
)


@pytest.mark.asyncio
async def test_hsts_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await hsts_missing(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_hsts_missing_present():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    message = await hsts_missing(response)

    assert message == "Strict-Transport-Security (HSTS) present"


@pytest.mark.asyncio
async def test_hsts_invalid_header_absent():
    response = Response(200)

    message = await hsts_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_invalid_invalid():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    with pytest.raises(ValidationError) as exc_info:
        await hsts_invalid(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) header is malformed"
    assert exc_info.value.metadata == {"value": "garbage"}


@pytest.mark.asyncio
async def test_hsts_invalid_valid():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    message = await hsts_invalid(response)

    assert message == "Strict-Transport-Security (HSTS) header is valid"


@pytest.mark.asyncio
async def test_hsts_max_age_zero_header_absent():
    response = Response(200)

    message = await hsts_max_age_zero(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_max_age_zero_invalid_header():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    message = await hsts_max_age_zero(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_max_age_zero_zero():
    response = Response(200, headers={"strict-transport-security": "max-age=0"})

    with pytest.raises(ValidationError) as exc_info:
        await hsts_max_age_zero(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) max-age is zero"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_hsts_max_age_zero_non_zero():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    message = await hsts_max_age_zero(response)

    assert message == "Strict-Transport-Security (HSTS) max-age is non-zero"


@pytest.mark.asyncio
async def test_hsts_max_age_low_header_absent():
    response = Response(200)

    message = await hsts_max_age_low(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_max_age_low_invalid_header():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    message = await hsts_max_age_low(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_max_age_low_zero():
    response = Response(200, headers={"strict-transport-security": "max-age=0"})

    message = await hsts_max_age_low(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_max_age_low_low():
    response = Response(200, headers={"strict-transport-security": "max-age=86400"})

    with pytest.raises(ValidationError) as exc_info:
        await hsts_max_age_low(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) max-age is less than one year"
    assert exc_info.value.metadata == {"max_age": "86400"}


@pytest.mark.asyncio
async def test_hsts_max_age_low_at_minimum():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    message = await hsts_max_age_low(response)

    assert message == "Strict-Transport-Security (HSTS) max-age meets minimum"


@pytest.mark.asyncio
async def test_hsts_max_age_low_above_minimum():
    response = Response(200, headers={"strict-transport-security": "max-age=63072000"})

    message = await hsts_max_age_low(response)

    assert message == "Strict-Transport-Security (HSTS) max-age meets minimum"


@pytest.mark.asyncio
async def test_hsts_include_subdomains_missing_header_absent():
    response = Response(200)

    message = await hsts_include_subdomains_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_include_subdomains_missing_invalid_header():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    message = await hsts_include_subdomains_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_include_subdomains_missing_missing():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000"})

    with pytest.raises(ValidationError) as exc_info:
        await hsts_include_subdomains_missing(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) includeSubDomains missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_hsts_include_subdomains_missing_present():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})

    message = await hsts_include_subdomains_missing(response)

    assert message == "Strict-Transport-Security (HSTS) includeSubDomains present"


@pytest.mark.asyncio
async def test_hsts_preload_not_eligible_header_absent():
    response = Response(200)

    message = await hsts_preload_not_eligible(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_preload_not_eligible_invalid_header():
    response = Response(200, headers={"strict-transport-security": "garbage"})

    message = await hsts_preload_not_eligible(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_preload_not_eligible_preload_absent():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})

    message = await hsts_preload_not_eligible(response)

    assert message is None


@pytest.mark.asyncio
async def test_hsts_preload_not_eligible_max_age_too_low():
    response = Response(200, headers={"strict-transport-security": "max-age=86400; includeSubDomains; preload"})

    with pytest.raises(ValidationError) as exc_info:
        await hsts_preload_not_eligible(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) does not meet preload requirements"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_hsts_preload_not_eligible_include_subdomains_missing():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000; preload"})

    with pytest.raises(ValidationError) as exc_info:
        await hsts_preload_not_eligible(response)

    assert exc_info.value.message == "Strict-Transport-Security (HSTS) does not meet preload requirements"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_hsts_preload_not_eligible_eligible():
    response = Response(200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains; preload"})

    message = await hsts_preload_not_eligible(response)

    assert message == "Strict-Transport-Security (HSTS) meets preload requirements"


@pytest.mark.asyncio
async def test_csp_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await csp_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_missing_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await csp_missing(response)

    assert message == "Content-Security-Policy (CSP) present"


@pytest.mark.asyncio
async def test_csp_unsafe_inline_no_csp():
    response = Response(200)

    message = await csp_unsafe_inline(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_unsafe_inline_unsafe_inline_in_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self' 'unsafe-inline'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_unsafe_inline(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_unsafe_inline_unsafe_inline_neutralized_by_nonce():
    response = Response(200, headers={"content-security-policy": "script-src 'nonce-abc123' 'unsafe-inline'"})

    message = await csp_unsafe_inline(response)

    assert message == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"


@pytest.mark.asyncio
async def test_csp_unsafe_inline_unsafe_inline_neutralized_by_hash():
    response = Response(200, headers={"content-security-policy": "script-src 'sha256-abc123=' 'unsafe-inline'"})

    message = await csp_unsafe_inline(response)

    assert message == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"


@pytest.mark.asyncio
async def test_csp_unsafe_inline_unsafe_inline_neutralized_by_strict_dynamic():
    response = Response(
        200,
        headers={"content-security-policy": "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline'"},
    )

    message = await csp_unsafe_inline(response)

    assert message == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"


@pytest.mark.asyncio
async def test_csp_unsafe_inline_via_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_unsafe_inline(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_unsafe_inline_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await csp_unsafe_inline(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_unsafe_inline_clean_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await csp_unsafe_inline(response)

    assert message == "Content-Security-Policy (CSP) script-src does not contain 'unsafe-inline'"


@pytest.mark.asyncio
async def test_csp_ro_unsafe_inline_no_header():
    response = Response(200)

    message = await csp_ro_unsafe_inline(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_unsafe_inline_unsafe_inline_in_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self' 'unsafe-inline'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_unsafe_inline(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_unsafe_inline_unsafe_inline_neutralized_by_nonce():
    response = Response(
        200,
        headers={"content-security-policy-report-only": "script-src 'nonce-abc123' 'unsafe-inline'"},
    )

    message = await csp_ro_unsafe_inline(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) 'unsafe-inline' is neutralized by nonce or hash"


@pytest.mark.asyncio
async def test_csp_ro_unsafe_inline_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    message = await csp_ro_unsafe_inline(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_unsafe_inline_clean_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    message = await csp_ro_unsafe_inline(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-inline'"


@pytest.mark.asyncio
async def test_csp_unsafe_eval_no_csp():
    response = Response(200)

    message = await csp_unsafe_eval(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_unsafe_eval_unsafe_eval_in_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self' 'unsafe-eval'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_unsafe_eval(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-eval'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_unsafe_eval_via_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-eval'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_unsafe_eval(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-eval'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_unsafe_eval_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await csp_unsafe_eval(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_unsafe_eval_clean_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await csp_unsafe_eval(response)

    assert message == "Content-Security-Policy (CSP) script-src does not contain 'unsafe-eval'"


@pytest.mark.asyncio
async def test_csp_ro_unsafe_eval_no_header():
    response = Response(200)

    message = await csp_ro_unsafe_eval(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_unsafe_eval_unsafe_eval_in_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self' 'unsafe-eval'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_unsafe_eval(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) script-src contains 'unsafe-eval'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_unsafe_eval_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    message = await csp_ro_unsafe_eval(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_unsafe_eval_clean_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    message = await csp_ro_unsafe_eval(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) script-src does not contain 'unsafe-eval'"


@pytest.mark.asyncio
async def test_csp_object_src_unsafe_no_csp():
    response = Response(200)

    message = await csp_object_src_unsafe(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_object_src_unsafe_object_src_none():
    response = Response(200, headers={"content-security-policy": "object-src 'none'"})

    message = await csp_object_src_unsafe(response)

    assert message == "Content-Security-Policy (CSP) object-src is restricted to 'none'"


@pytest.mark.asyncio
async def test_csp_object_src_unsafe_object_src_self():
    response = Response(200, headers={"content-security-policy": "object-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_object_src_unsafe_no_object_src_default_src_none():
    response = Response(200, headers={"content-security-policy": "default-src 'none'"})

    message = await csp_object_src_unsafe(response)

    assert message == "Content-Security-Policy (CSP) object-src is restricted to 'none'"


@pytest.mark.asyncio
async def test_csp_object_src_unsafe_no_object_src_default_src_self():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_object_src_unsafe_no_object_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_object_src_unsafe_no_header():
    response = Response(200)

    message = await csp_ro_object_src_unsafe(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_object_src_unsafe_object_src_none():
    response = Response(200, headers={"content-security-policy-report-only": "object-src 'none'"})

    message = await csp_ro_object_src_unsafe(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) object-src is restricted to 'none'"


@pytest.mark.asyncio
async def test_csp_ro_object_src_unsafe_object_src_self():
    response = Response(200, headers={"content-security-policy-report-only": "object-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_object_src_unsafe_no_object_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_object_src_unsafe(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_base_uri_missing_no_csp():
    response = Response(200)

    message = await csp_base_uri_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_base_uri_missing_base_uri_absent():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_base_uri_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) base-uri is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_base_uri_missing_base_uri_none():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; base-uri 'none'"})

    message = await csp_base_uri_missing(response)

    assert message == "Content-Security-Policy (CSP) base-uri is present"


@pytest.mark.asyncio
async def test_csp_base_uri_missing_base_uri_self():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; base-uri 'self'"})

    message = await csp_base_uri_missing(response)

    assert message == "Content-Security-Policy (CSP) base-uri is present"


@pytest.mark.asyncio
async def test_csp_ro_base_uri_missing_no_header():
    response = Response(200)

    message = await csp_ro_base_uri_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_base_uri_missing_base_uri_absent():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_base_uri_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) base-uri is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_base_uri_missing_base_uri_present():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'; base-uri 'none'"})

    message = await csp_ro_base_uri_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) base-uri is present"


@pytest.mark.asyncio
async def test_csp_frame_ancestors_missing_no_csp():
    response = Response(200)

    message = await csp_frame_ancestors_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_frame_ancestors_missing_frame_ancestors_absent():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_frame_ancestors_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) frame-ancestors is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_frame_ancestors_missing_frame_ancestors_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; frame-ancestors 'self'"})

    message = await csp_frame_ancestors_missing(response)

    assert message == "Content-Security-Policy (CSP) frame-ancestors is present"


@pytest.mark.asyncio
async def test_csp_ro_frame_ancestors_missing_no_header():
    response = Response(200)

    message = await csp_ro_frame_ancestors_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_frame_ancestors_missing_frame_ancestors_absent():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_frame_ancestors_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) frame-ancestors is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_frame_ancestors_missing_frame_ancestors_present():
    response = Response(
        200, headers={"content-security-policy-report-only": "default-src 'self'; frame-ancestors 'self'"}
    )

    message = await csp_ro_frame_ancestors_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) frame-ancestors is present"


@pytest.mark.asyncio
async def test_csp_form_action_missing_no_csp():
    response = Response(200)

    message = await csp_form_action_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_form_action_missing_form_action_absent():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_form_action_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) form-action is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_form_action_missing_form_action_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; form-action 'self'"})

    message = await csp_form_action_missing(response)

    assert message == "Content-Security-Policy (CSP) form-action is present"


@pytest.mark.asyncio
async def test_csp_ro_form_action_missing_no_header():
    response = Response(200)

    message = await csp_ro_form_action_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_form_action_missing_form_action_absent():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_form_action_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) form-action is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_form_action_missing_form_action_present():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'; form-action 'self'"})

    message = await csp_ro_form_action_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) form-action is present"


@pytest.mark.asyncio
async def test_csp_script_src_missing_no_csp():
    response = Response(200)

    message = await csp_script_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_script_src_missing_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_script_src_missing_script_src_present():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await csp_script_src_missing(response)

    assert message == "Content-Security-Policy (CSP) script-src is present"


@pytest.mark.asyncio
async def test_csp_script_src_missing_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await csp_script_src_missing(response)

    assert message == "Content-Security-Policy (CSP) script-src is present"


@pytest.mark.asyncio
async def test_csp_ro_script_src_missing_no_header():
    response = Response(200)

    message = await csp_ro_script_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_script_src_missing_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_script_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) script-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_script_src_missing_script_src_present():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    message = await csp_ro_script_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) script-src is present"


@pytest.mark.asyncio
async def test_csp_script_src_unrestricted_no_csp():
    response = Response(200)

    message = await csp_script_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_script_src_unrestricted_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await csp_script_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_script_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy": "script-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_script_src_unrestricted_wildcard_https():
    response = Response(200, headers={"content-security-policy": "script-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_script_src_unrestricted_wildcard_http():
    response = Response(200, headers={"content-security-policy": "script-src http:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_script_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_script_src_unrestricted_clean_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await csp_script_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) script-src is restricted"


@pytest.mark.asyncio
async def test_csp_script_src_unrestricted_wildcard_only_in_other_directive():
    response = Response(200, headers={"content-security-policy": "script-src 'self'; img-src *"})

    message = await csp_script_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) script-src is restricted"


@pytest.mark.asyncio
async def test_csp_ro_script_src_unrestricted_no_header():
    response = Response(200)

    message = await csp_ro_script_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_script_src_unrestricted_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    message = await csp_ro_script_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_script_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy-report-only": "script-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_script_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) script-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_script_src_unrestricted_clean_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src 'self'"})

    message = await csp_ro_script_src_unrestricted(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) script-src is restricted"


@pytest.mark.asyncio
async def test_csp_style_src_missing_no_csp():
    response = Response(200)

    message = await csp_style_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_style_src_missing_no_style_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_style_src_missing_style_src_present():
    response = Response(200, headers={"content-security-policy": "style-src 'self'"})

    message = await csp_style_src_missing(response)

    assert message == "Content-Security-Policy (CSP) style-src is present"


@pytest.mark.asyncio
async def test_csp_style_src_missing_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await csp_style_src_missing(response)

    assert message == "Content-Security-Policy (CSP) style-src is present"


@pytest.mark.asyncio
async def test_csp_style_src_unrestricted_no_csp():
    response = Response(200)

    message = await csp_style_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_style_src_unrestricted_no_style_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await csp_style_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_style_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy": "style-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_style_src_unrestricted_wildcard_https():
    response = Response(200, headers={"content-security-policy": "style-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_style_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_style_src_unrestricted_clean_style_src():
    response = Response(200, headers={"content-security-policy": "style-src 'self'"})

    message = await csp_style_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) style-src is restricted"


@pytest.mark.asyncio
async def test_csp_ro_style_src_missing_no_header():
    response = Response(200)

    message = await csp_ro_style_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_style_src_missing_no_style_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_style_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) style-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_style_src_missing_style_src_present():
    response = Response(200, headers={"content-security-policy-report-only": "style-src 'self'"})

    message = await csp_ro_style_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) style-src is present"


@pytest.mark.asyncio
async def test_csp_ro_style_src_unrestricted_no_header():
    response = Response(200)

    message = await csp_ro_style_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_style_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy-report-only": "style-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_style_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) style-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_style_src_unrestricted_clean_style_src():
    response = Response(200, headers={"content-security-policy-report-only": "style-src 'self'"})

    message = await csp_ro_style_src_unrestricted(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) style-src is restricted"


@pytest.mark.asyncio
async def test_csp_connect_src_missing_no_csp():
    response = Response(200)

    message = await csp_connect_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_connect_src_missing_no_connect_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_connect_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_connect_src_missing_connect_src_present():
    response = Response(200, headers={"content-security-policy": "connect-src 'self'"})

    message = await csp_connect_src_missing(response)

    assert message == "Content-Security-Policy (CSP) connect-src is present"


@pytest.mark.asyncio
async def test_csp_connect_src_missing_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await csp_connect_src_missing(response)

    assert message == "Content-Security-Policy (CSP) connect-src is present"


@pytest.mark.asyncio
async def test_csp_connect_src_unrestricted_no_csp():
    response = Response(200)

    message = await csp_connect_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_connect_src_unrestricted_no_connect_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await csp_connect_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_connect_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy": "connect-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_connect_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_connect_src_unrestricted_wildcard_https():
    response = Response(200, headers={"content-security-policy": "connect-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_connect_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_connect_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_connect_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_connect_src_unrestricted_clean_connect_src():
    response = Response(200, headers={"content-security-policy": "connect-src 'self'"})

    message = await csp_connect_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) connect-src is restricted"


@pytest.mark.asyncio
async def test_csp_ro_connect_src_missing_no_header():
    response = Response(200)

    message = await csp_ro_connect_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_connect_src_missing_no_connect_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_connect_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) connect-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_connect_src_missing_connect_src_present():
    response = Response(200, headers={"content-security-policy-report-only": "connect-src 'self'"})

    message = await csp_ro_connect_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) connect-src is present"


@pytest.mark.asyncio
async def test_csp_ro_connect_src_unrestricted_no_header():
    response = Response(200)

    message = await csp_ro_connect_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_connect_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy-report-only": "connect-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_connect_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) connect-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_connect_src_unrestricted_clean_connect_src():
    response = Response(200, headers={"content-security-policy-report-only": "connect-src 'self'"})

    message = await csp_ro_connect_src_unrestricted(response)

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


@pytest.mark.asyncio
async def test_access_control_allow_credentials_wildcard_no_cors_header():
    response = Response(200)

    message = await access_control_allow_credentials_wildcard(response)

    assert message is None


@pytest.mark.asyncio
async def test_access_control_allow_credentials_wildcard_specific_origin_with_credentials():
    response = Response(
        200,
        headers={
            "access-control-allow-origin": "https://example.com",
            "access-control-allow-credentials": "true",
        },
    )

    message = await access_control_allow_credentials_wildcard(response)

    assert message is None


@pytest.mark.asyncio
async def test_access_control_allow_credentials_wildcard_wildcard_without_credentials():
    response = Response(200, headers={"access-control-allow-origin": "*"})

    message = await access_control_allow_credentials_wildcard(response)

    assert message == "Access-Control-Allow-Origin wildcard does not enable credentials"


@pytest.mark.asyncio
async def test_access_control_allow_credentials_wildcard_wildcard_with_credentials():
    response = Response(
        200,
        headers={
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
    )

    with pytest.raises(ValidationError) as exc_info:
        await access_control_allow_credentials_wildcard(response)

    assert exc_info.value.message == "Access-Control-Allow-Origin is wildcard with credentials enabled"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_access_control_allow_credentials_invalid_header_absent():
    response = Response(200)

    message = await access_control_allow_credentials_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_access_control_allow_credentials_invalid_valid_lowercase():
    response = Response(200, headers={"access-control-allow-credentials": "true"})

    message = await access_control_allow_credentials_invalid(response)

    assert message == "Access-Control-Allow-Credentials has a valid value"


@pytest.mark.asyncio
async def test_access_control_allow_credentials_invalid_valid_uppercase():
    response = Response(200, headers={"access-control-allow-credentials": "TRUE"})

    message = await access_control_allow_credentials_invalid(response)

    assert message == "Access-Control-Allow-Credentials has a valid value"


@pytest.mark.asyncio
async def test_access_control_allow_credentials_invalid_invalid_value():
    response = Response(200, headers={"access-control-allow-credentials": "1"})

    with pytest.raises(ValidationError) as exc_info:
        await access_control_allow_credentials_invalid(response)

    assert exc_info.value.message == "Access-Control-Allow-Credentials has an invalid value"
    assert exc_info.value.metadata == {"value": "1"}


@pytest.mark.asyncio
async def test_access_control_allow_credentials_invalid_false_value():
    response = Response(200, headers={"access-control-allow-credentials": "false"})

    with pytest.raises(ValidationError) as exc_info:
        await access_control_allow_credentials_invalid(response)

    assert exc_info.value.message == "Access-Control-Allow-Credentials has an invalid value"
    assert exc_info.value.metadata == {"value": "false"}


@pytest.mark.asyncio
async def test_access_control_allow_methods_unsafe_header_absent():
    response = Response(200)

    message = await access_control_allow_methods_unsafe(response)

    assert message is None


@pytest.mark.asyncio
async def test_access_control_allow_methods_unsafe_safe_methods():
    response = Response(200, headers={"access-control-allow-methods": "GET, POST, OPTIONS"})

    message = await access_control_allow_methods_unsafe(response)

    assert message == "Access-Control-Allow-Methods does not include unsafe methods"


@pytest.mark.asyncio
async def test_access_control_allow_methods_unsafe_delete():
    response = Response(200, headers={"access-control-allow-methods": "GET, DELETE"})

    with pytest.raises(ValidationError) as exc_info:
        await access_control_allow_methods_unsafe(response)

    assert exc_info.value.message == "Access-Control-Allow-Methods includes unsafe methods"
    assert exc_info.value.metadata == {"methods": "DELETE"}


@pytest.mark.asyncio
async def test_access_control_allow_methods_unsafe_multiple_unsafe():
    response = Response(200, headers={"access-control-allow-methods": "GET, PUT, DELETE, PATCH"})

    with pytest.raises(ValidationError) as exc_info:
        await access_control_allow_methods_unsafe(response)

    assert exc_info.value.message == "Access-Control-Allow-Methods includes unsafe methods"
    assert exc_info.value.metadata == {"methods": "DELETE, PATCH, PUT"}


@pytest.mark.asyncio
async def test_access_control_max_age_excessive_header_absent():
    response = Response(200)

    message = await access_control_max_age_excessive(response)

    assert message is None


@pytest.mark.asyncio
async def test_access_control_max_age_excessive_invalid_value():
    response = Response(200, headers={"access-control-max-age": "notanumber"})

    message = await access_control_max_age_excessive(response)

    assert message is None


@pytest.mark.asyncio
async def test_access_control_max_age_excessive_within_limit():
    response = Response(200, headers={"access-control-max-age": "7200"})

    message = await access_control_max_age_excessive(response)

    assert message == "Access-Control-Max-Age is within browser cache limits"


@pytest.mark.asyncio
async def test_access_control_max_age_excessive_at_limit():
    response = Response(200, headers={"access-control-max-age": "86400"})

    message = await access_control_max_age_excessive(response)

    assert message == "Access-Control-Max-Age is within browser cache limits"


@pytest.mark.asyncio
async def test_access_control_max_age_excessive_excessive():
    response = Response(200, headers={"access-control-max-age": "86401"})

    with pytest.raises(ValidationError) as exc_info:
        await access_control_max_age_excessive(response)

    assert exc_info.value.message == "Access-Control-Max-Age exceeds browser cache limits"
    assert exc_info.value.metadata == {"max_age": "86401"}


@pytest.mark.asyncio
async def test_corp_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await corp_missing(response)

    assert exc_info.value.message == "Cross-Origin-Resource-Policy (CORP) missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_corp_missing_present():
    response = Response(200, headers={"cross-origin-resource-policy": "same-origin"})

    message = await corp_missing(response)

    assert message == "Cross-Origin-Resource-Policy (CORP) present"


@pytest.mark.asyncio
async def test_corp_invalid_header_absent():
    response = Response(200)

    message = await corp_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_corp_invalid_valid_same_origin():
    response = Response(200, headers={"cross-origin-resource-policy": "same-origin"})

    message = await corp_invalid(response)

    assert message == "Cross-Origin-Resource-Policy (CORP) header is valid"


@pytest.mark.parametrize(
    "value",
    [
        "invalid",
        "Same-Origin",
        "same-origin, same-site",
        "same-origin, cross-origin",
    ],
)
@pytest.mark.asyncio
async def test_corp_invalid_invalid_values(value: str):
    response = Response(200, headers={"cross-origin-resource-policy": value})

    with pytest.raises(ValidationError) as exc_info:
        await corp_invalid(response)

    assert exc_info.value.message == "Cross-Origin-Resource-Policy (CORP) header is invalid"
    assert exc_info.value.metadata == {"value": value}


@pytest.mark.asyncio
async def test_corp_same_site_header_absent():
    response = Response(200)

    message = await corp_same_site(response)

    assert message is None


@pytest.mark.asyncio
async def test_corp_same_site_invalid_value():
    response = Response(200, headers={"cross-origin-resource-policy": "invalid"})

    message = await corp_same_site(response)

    assert message is None


@pytest.mark.asyncio
async def test_corp_same_site_same_site():
    response = Response(200, headers={"cross-origin-resource-policy": "same-site"})

    with pytest.raises(ValidationError) as exc_info:
        await corp_same_site(response)

    assert exc_info.value.message == "Cross-Origin-Resource-Policy (CORP) is same-site"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_corp_same_site_same_origin():
    response = Response(200, headers={"cross-origin-resource-policy": "same-origin"})

    message = await corp_same_site(response)

    assert message == "Cross-Origin-Resource-Policy (CORP) is not same-site"


@pytest.mark.asyncio
async def test_corp_cross_origin_header_absent():
    response = Response(200)

    message = await corp_cross_origin(response)

    assert message is None


@pytest.mark.asyncio
async def test_corp_cross_origin_invalid_value():
    response = Response(200, headers={"cross-origin-resource-policy": "invalid"})

    message = await corp_cross_origin(response)

    assert message is None


@pytest.mark.asyncio
async def test_corp_cross_origin_cross_origin():
    response = Response(200, headers={"cross-origin-resource-policy": "cross-origin"})

    with pytest.raises(ValidationError) as exc_info:
        await corp_cross_origin(response)

    assert exc_info.value.message == "Cross-Origin-Resource-Policy (CORP) is cross-origin"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_corp_cross_origin_same_origin():
    response = Response(200, headers={"cross-origin-resource-policy": "same-origin"})

    message = await corp_cross_origin(response)

    assert message == "Cross-Origin-Resource-Policy (CORP) is not cross-origin"


@pytest.mark.asyncio
async def test_coep_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await coep_missing(response)

    assert exc_info.value.message == "Cross-Origin-Embedder-Policy (COEP) missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coep_missing_present():
    response = Response(200, headers={"cross-origin-embedder-policy": "require-corp"})

    message = await coep_missing(response)

    assert message == "Cross-Origin-Embedder-Policy (COEP) present"


@pytest.mark.asyncio
async def test_coep_invalid_header_absent():
    response = Response(200)

    message = await coep_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_coep_invalid_valid():
    response = Response(200, headers={"cross-origin-embedder-policy": "require-corp"})

    message = await coep_invalid(response)

    assert message == "Cross-Origin-Embedder-Policy (COEP) header is valid"


@pytest.mark.asyncio
async def test_coep_invalid_invalid():
    value = "invalid"
    response = Response(200, headers={"cross-origin-embedder-policy": value})

    with pytest.raises(ValidationError) as exc_info:
        await coep_invalid(response)

    assert exc_info.value.message == "Cross-Origin-Embedder-Policy (COEP) header is invalid"
    assert exc_info.value.metadata == {"value": value}


@pytest.mark.asyncio
async def test_coep_unsafe_none_header_absent():
    response = Response(200)

    message = await coep_unsafe_none(response)

    assert message is None


@pytest.mark.asyncio
async def test_coep_unsafe_none_invalid_value():
    response = Response(200, headers={"cross-origin-embedder-policy": "invalid"})

    message = await coep_unsafe_none(response)

    assert message is None


@pytest.mark.asyncio
async def test_coep_unsafe_none_unsafe_none():
    response = Response(200, headers={"cross-origin-embedder-policy": "unsafe-none"})

    with pytest.raises(ValidationError) as exc_info:
        await coep_unsafe_none(response)

    assert exc_info.value.message == "Cross-Origin-Embedder-Policy (COEP) is unsafe-none"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coep_unsafe_none_require_corp():
    response = Response(200, headers={"cross-origin-embedder-policy": "require-corp"})

    message = await coep_unsafe_none(response)

    assert message == "Cross-Origin-Embedder-Policy (COEP) is not unsafe-none"


@pytest.mark.asyncio
async def test_coep_credentialless_header_absent():
    response = Response(200)

    message = await coep_credentialless(response)

    assert message is None


@pytest.mark.asyncio
async def test_coep_credentialless_invalid_value():
    response = Response(200, headers={"cross-origin-embedder-policy": "invalid"})

    message = await coep_credentialless(response)

    assert message is None


@pytest.mark.asyncio
async def test_coep_credentialless_credentialless():
    response = Response(200, headers={"cross-origin-embedder-policy": "credentialless"})

    with pytest.raises(ValidationError) as exc_info:
        await coep_credentialless(response)

    assert exc_info.value.message == "Cross-Origin-Embedder-Policy (COEP) is credentialless"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coep_credentialless_require_corp():
    response = Response(200, headers={"cross-origin-embedder-policy": "require-corp"})

    message = await coep_credentialless(response)

    assert message == "Cross-Origin-Embedder-Policy (COEP) is not credentialless"


@pytest.mark.asyncio
async def test_coep_ro_invalid_header_absent():
    response = Response(200)

    message = await coep_ro_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_coep_ro_invalid_valid():
    response = Response(200, headers={"cross-origin-embedder-policy-report-only": "require-corp"})

    message = await coep_ro_invalid(response)

    assert message == "Cross-Origin-Embedder-Policy-Report-Only (COEP) header is valid"


@pytest.mark.asyncio
async def test_coep_ro_invalid_invalid():
    value = "invalid"
    response = Response(200, headers={"cross-origin-embedder-policy-report-only": value})

    with pytest.raises(ValidationError) as exc_info:
        await coep_ro_invalid(response)

    assert exc_info.value.message == "Cross-Origin-Embedder-Policy-Report-Only (COEP) header is invalid"
    assert exc_info.value.metadata == {"value": value}


@pytest.mark.asyncio
async def test_coep_ro_unsafe_none_header_absent():
    response = Response(200)

    message = await coep_ro_unsafe_none(response)

    assert message is None


@pytest.mark.asyncio
async def test_coep_ro_unsafe_none_unsafe_none():
    response = Response(200, headers={"cross-origin-embedder-policy-report-only": "unsafe-none"})

    with pytest.raises(ValidationError) as exc_info:
        await coep_ro_unsafe_none(response)

    assert exc_info.value.message == "Cross-Origin-Embedder-Policy-Report-Only (COEP) is unsafe-none"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coep_ro_unsafe_none_require_corp():
    response = Response(200, headers={"cross-origin-embedder-policy-report-only": "require-corp"})

    message = await coep_ro_unsafe_none(response)

    assert message == "Cross-Origin-Embedder-Policy-Report-Only (COEP) is not unsafe-none"


@pytest.mark.asyncio
async def test_coep_ro_credentialless_header_absent():
    response = Response(200)

    message = await coep_ro_credentialless(response)

    assert message is None


@pytest.mark.asyncio
async def test_coep_ro_credentialless_credentialless():
    response = Response(200, headers={"cross-origin-embedder-policy-report-only": "credentialless"})

    with pytest.raises(ValidationError) as exc_info:
        await coep_ro_credentialless(response)

    assert exc_info.value.message == "Cross-Origin-Embedder-Policy-Report-Only (COEP) is credentialless"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coep_ro_credentialless_require_corp():
    response = Response(200, headers={"cross-origin-embedder-policy-report-only": "require-corp"})

    message = await coep_ro_credentialless(response)

    assert message == "Cross-Origin-Embedder-Policy-Report-Only (COEP) is not credentialless"


@pytest.mark.asyncio
async def test_coop_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await coop_missing(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy (COOP) missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coop_missing_present():
    response = Response(200, headers={"cross-origin-opener-policy": "same-origin"})

    message = await coop_missing(response)

    assert message == "Cross-Origin-Opener-Policy (COOP) present"


@pytest.mark.asyncio
async def test_coop_invalid_header_absent():
    response = Response(200)

    message = await coop_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_invalid_valid():
    response = Response(200, headers={"cross-origin-opener-policy": "same-origin"})

    message = await coop_invalid(response)

    assert message == "Cross-Origin-Opener-Policy (COOP) header is valid"


@pytest.mark.asyncio
async def test_coop_invalid_invalid():
    value = "invalid"
    response = Response(200, headers={"cross-origin-opener-policy": value})

    with pytest.raises(ValidationError) as exc_info:
        await coop_invalid(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy (COOP) header is invalid"
    assert exc_info.value.metadata == {"value": value}


@pytest.mark.asyncio
async def test_coop_unsafe_none_header_absent():
    response = Response(200)

    message = await coop_unsafe_none(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_unsafe_none_invalid_value():
    response = Response(200, headers={"cross-origin-opener-policy": "invalid"})

    message = await coop_unsafe_none(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_unsafe_none_unsafe_none():
    response = Response(200, headers={"cross-origin-opener-policy": "unsafe-none"})

    with pytest.raises(ValidationError) as exc_info:
        await coop_unsafe_none(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy (COOP) is unsafe-none"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coop_unsafe_none_same_origin():
    response = Response(200, headers={"cross-origin-opener-policy": "same-origin"})

    message = await coop_unsafe_none(response)

    assert message == "Cross-Origin-Opener-Policy (COOP) is not unsafe-none"


@pytest.mark.asyncio
async def test_coop_same_origin_allow_popups_header_absent():
    response = Response(200)

    message = await coop_same_origin_allow_popups(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_same_origin_allow_popups_same_origin_allow_popups():
    response = Response(200, headers={"cross-origin-opener-policy": "same-origin-allow-popups"})

    with pytest.raises(ValidationError) as exc_info:
        await coop_same_origin_allow_popups(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy (COOP) is same-origin-allow-popups"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coop_same_origin_allow_popups_same_origin():
    response = Response(200, headers={"cross-origin-opener-policy": "same-origin"})

    message = await coop_same_origin_allow_popups(response)

    assert message == "Cross-Origin-Opener-Policy (COOP) is not same-origin-allow-popups"


@pytest.mark.asyncio
async def test_coop_noopener_allow_popups_header_absent():
    response = Response(200)

    message = await coop_noopener_allow_popups(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_noopener_allow_popups_noopener_allow_popups():
    response = Response(200, headers={"cross-origin-opener-policy": "noopener-allow-popups"})

    with pytest.raises(ValidationError) as exc_info:
        await coop_noopener_allow_popups(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy (COOP) is noopener-allow-popups"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coop_noopener_allow_popups_same_origin():
    response = Response(200, headers={"cross-origin-opener-policy": "same-origin"})

    message = await coop_noopener_allow_popups(response)

    assert message == "Cross-Origin-Opener-Policy (COOP) is not noopener-allow-popups"


@pytest.mark.asyncio
async def test_coop_ro_invalid_header_absent():
    response = Response(200)

    message = await coop_ro_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_ro_invalid_valid():
    response = Response(200, headers={"cross-origin-opener-policy-report-only": "same-origin"})

    message = await coop_ro_invalid(response)

    assert message == "Cross-Origin-Opener-Policy-Report-Only (COOP) header is valid"


@pytest.mark.asyncio
async def test_coop_ro_invalid_invalid():
    value = "invalid"
    response = Response(200, headers={"cross-origin-opener-policy-report-only": value})

    with pytest.raises(ValidationError) as exc_info:
        await coop_ro_invalid(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy-Report-Only (COOP) header is invalid"
    assert exc_info.value.metadata == {"value": value}


@pytest.mark.asyncio
async def test_coop_ro_unsafe_none_header_absent():
    response = Response(200)

    message = await coop_ro_unsafe_none(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_ro_unsafe_none_unsafe_none():
    response = Response(200, headers={"cross-origin-opener-policy-report-only": "unsafe-none"})

    with pytest.raises(ValidationError) as exc_info:
        await coop_ro_unsafe_none(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy-Report-Only (COOP) is unsafe-none"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coop_ro_unsafe_none_same_origin():
    response = Response(200, headers={"cross-origin-opener-policy-report-only": "same-origin"})

    message = await coop_ro_unsafe_none(response)

    assert message == "Cross-Origin-Opener-Policy-Report-Only (COOP) is not unsafe-none"


@pytest.mark.asyncio
async def test_coop_ro_same_origin_allow_popups_header_absent():
    response = Response(200)

    message = await coop_ro_same_origin_allow_popups(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_ro_same_origin_allow_popups_same_origin_allow_popups():
    response = Response(200, headers={"cross-origin-opener-policy-report-only": "same-origin-allow-popups"})

    with pytest.raises(ValidationError) as exc_info:
        await coop_ro_same_origin_allow_popups(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy-Report-Only (COOP) is same-origin-allow-popups"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coop_ro_same_origin_allow_popups_same_origin():
    response = Response(200, headers={"cross-origin-opener-policy-report-only": "same-origin"})

    message = await coop_ro_same_origin_allow_popups(response)

    assert message == "Cross-Origin-Opener-Policy-Report-Only (COOP) is not same-origin-allow-popups"


@pytest.mark.asyncio
async def test_coop_ro_noopener_allow_popups_header_absent():
    response = Response(200)

    message = await coop_ro_noopener_allow_popups(response)

    assert message is None


@pytest.mark.asyncio
async def test_coop_ro_noopener_allow_popups_noopener_allow_popups():
    response = Response(200, headers={"cross-origin-opener-policy-report-only": "noopener-allow-popups"})

    with pytest.raises(ValidationError) as exc_info:
        await coop_ro_noopener_allow_popups(response)

    assert exc_info.value.message == "Cross-Origin-Opener-Policy-Report-Only (COOP) is noopener-allow-popups"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_coop_ro_noopener_allow_popups_same_origin():
    response = Response(200, headers={"cross-origin-opener-policy-report-only": "same-origin"})

    message = await coop_ro_noopener_allow_popups(response)

    assert message == "Cross-Origin-Opener-Policy-Report-Only (COOP) is not noopener-allow-popups"


@pytest.mark.asyncio
async def test_x_content_type_options_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await x_content_type_options_missing(response)

    assert exc_info.value.message == "X-Content-Type-Options header missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_x_content_type_options_missing_present():
    response = Response(200, headers={"x-content-type-options": "nosniff"})

    message = await x_content_type_options_missing(response)

    assert message == "X-Content-Type-Options header present"


@pytest.mark.asyncio
async def test_x_content_type_options_invalid_header_absent():
    response = Response(200)

    message = await x_content_type_options_invalid(response)

    assert message is None


@pytest.mark.asyncio
async def test_x_content_type_options_invalid_invalid():
    response = Response(200, headers={"x-content-type-options": "sniff"})

    with pytest.raises(ValidationError) as exc_info:
        await x_content_type_options_invalid(response)

    assert exc_info.value.message == "X-Content-Type-Options header is invalid"
    assert exc_info.value.metadata == {"value": "sniff"}


@pytest.mark.asyncio
async def test_x_content_type_options_invalid_duplicated_header():
    response = Response(200, headers=[("x-content-type-options", "nosniff"), ("x-content-type-options", "nosniff")])

    with pytest.raises(ValidationError) as exc_info:
        await x_content_type_options_invalid(response)

    assert exc_info.value.message == "X-Content-Type-Options header is invalid"
    assert exc_info.value.metadata == {"value": "nosniff, nosniff"}


@pytest.mark.asyncio
async def test_x_content_type_options_invalid_valid():
    response = Response(200, headers={"x-content-type-options": "NoSnIfF"})

    message = await x_content_type_options_invalid(response)

    assert message == "X-Content-Type-Options header is valid"


@pytest.mark.asyncio
async def test_x_content_type_options_duplicated_header_absent():
    response = Response(200)

    message = await x_content_type_options_duplicated(response)

    assert message is None


@pytest.mark.asyncio
async def test_x_content_type_options_duplicated_single_header():
    response = Response(200, headers={"x-content-type-options": "nosniff"})

    message = await x_content_type_options_duplicated(response)

    assert message == "X-Content-Type-Options header is not duplicated"


@pytest.mark.asyncio
async def test_x_content_type_options_duplicated_duplicated():
    response = Response(200, headers=[("x-content-type-options", "nosniff"), ("x-content-type-options", "sniff")])

    with pytest.raises(ValidationError) as exc_info:
        await x_content_type_options_duplicated(response)

    assert exc_info.value.message == "X-Content-Type-Options header is duplicated"
    assert exc_info.value.metadata == {"values": "nosniff, sniff"}


@pytest.mark.asyncio
async def test_referrer_policy_missing_missing():
    response = Response(200)

    with pytest.raises(ValidationError) as exc_info:
        await referrer_policy_missing(response)

    assert exc_info.value.message == "Referrer-Policy header missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_referrer_policy_missing_present():
    response = Response(200, headers={"referrer-policy": "strict-origin-when-cross-origin"})

    message = await referrer_policy_missing(response)

    assert message == "Referrer-Policy header present"


@pytest.mark.asyncio
async def test_referrer_policy_invalid_header_absent():
    response = Response(200)

    message = await referrer_policy_invalid(response)

    assert message is None


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["invalid", "no-referrer, strict-origin-when-cross-origin"])
async def test_referrer_policy_invalid_invalid(value: str):
    response = Response(200, headers={"referrer-policy": value})

    with pytest.raises(ValidationError) as exc_info:
        await referrer_policy_invalid(response)

    assert exc_info.value.message == "Referrer-Policy header is invalid"
    assert exc_info.value.metadata == {"value": response.headers["referrer-policy"]}


@pytest.mark.asyncio
async def test_referrer_policy_invalid_valid():
    response = Response(200, headers={"referrer-policy": "  SAME-ORIGIN  "})

    message = await referrer_policy_invalid(response)

    assert message == "Referrer-Policy header is valid"


@pytest.mark.asyncio
async def test_referrer_policy_unsafe_header_absent():
    response = Response(200)

    message = await referrer_policy_unsafe(response)

    assert message is None


@pytest.mark.asyncio
async def test_referrer_policy_unsafe_invalid_header():
    response = Response(200, headers={"referrer-policy": "invalid"})

    message = await referrer_policy_unsafe(response)

    assert message is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "policy",
    [
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "unsafe-url",
    ],
)
async def test_referrer_policy_unsafe_unsafe(policy: str):
    response = Response(200, headers={"referrer-policy": policy})

    with pytest.raises(ValidationError) as exc_info:
        await referrer_policy_unsafe(response)

    assert exc_info.value.message == "Referrer-Policy is weaker than 'strict-origin-when-cross-origin'"
    assert exc_info.value.metadata == {"policy": policy}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "policy",
    [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ],
)
async def test_referrer_policy_unsafe_not_unsafe(policy: str):
    response = Response(200, headers={"referrer-policy": policy})

    message = await referrer_policy_unsafe(response)

    assert message == "Referrer-Policy is not weaker than 'strict-origin-when-cross-origin'"
