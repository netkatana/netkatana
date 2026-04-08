import pytest
from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.validators.http.headers import (
    content_security_policy_missing,
    content_security_policy_report_only_unsafe_eval,
    content_security_policy_report_only_unsafe_inline,
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
