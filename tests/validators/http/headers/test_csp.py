import pytest
from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.types import Validator
from netkatana.validators.http.headers.csp import (
    csp_base_uri_missing,
    csp_block_all_mixed_content_deprecated,
    csp_child_src_missing,
    csp_child_src_unrestricted,
    csp_connect_src_missing,
    csp_connect_src_unrestricted,
    csp_duplicated,
    csp_font_src_missing,
    csp_font_src_unrestricted,
    csp_form_action_missing,
    csp_frame_ancestors_missing,
    csp_img_src_missing,
    csp_img_src_unrestricted,
    csp_missing,
    csp_object_src_unsafe,
    csp_report_only_base_uri_missing,
    csp_report_only_block_all_mixed_content_deprecated,
    csp_report_only_child_src_missing,
    csp_report_only_child_src_unrestricted,
    csp_report_only_duplicated,
    csp_ro_connect_src_missing,
    csp_ro_connect_src_unrestricted,
    csp_ro_font_src_missing,
    csp_ro_font_src_unrestricted,
    csp_ro_form_action_missing,
    csp_ro_frame_ancestors_missing,
    csp_ro_img_src_missing,
    csp_ro_img_src_unrestricted,
    csp_ro_object_src_unsafe,
    csp_ro_script_src_missing,
    csp_ro_script_src_unrestricted,
    csp_ro_style_src_missing,
    csp_ro_style_src_unrestricted,
    csp_ro_unsafe_eval,
    csp_ro_unsafe_inline,
    csp_ro_worker_src_missing,
    csp_ro_worker_src_unrestricted,
    csp_script_src_missing,
    csp_script_src_unrestricted,
    csp_style_src_missing,
    csp_style_src_unrestricted,
    csp_unsafe_eval,
    csp_unsafe_inline,
    csp_worker_src_missing,
    csp_worker_src_unrestricted,
)


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
@pytest.mark.parametrize("validator", [csp_duplicated, csp_report_only_duplicated])
async def test_csp_duplicated_header_absent(validator: Validator):
    response = Response(200)

    message = await validator(response)

    assert message is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,validator,message",
    [
        ("content-security-policy", csp_duplicated, "Content-Security-Policy (CSP) header is not duplicated"),
        (
            "content-security-policy-report-only",
            csp_report_only_duplicated,
            "Content-Security-Policy-Report-Only (CSP) header is not duplicated",
        ),
    ],
)
async def test_csp_duplicated_single_header(header: str, validator: Validator, message: str):
    response = Response(200, headers={header: "default-src 'self'"})

    assert await validator(response) == message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,validator,message",
    [
        ("content-security-policy", csp_duplicated, "Content-Security-Policy (CSP) header is duplicated"),
        (
            "content-security-policy-report-only",
            csp_report_only_duplicated,
            "Content-Security-Policy-Report-Only (CSP) header is duplicated",
        ),
    ],
)
async def test_csp_duplicated_duplicated(header: str, validator: Validator, message: str):
    response = Response(200, headers=[(header, "default-src 'self'"), (header, "script-src 'self'")])

    with pytest.raises(ValidationError) as exc_info:
        await validator(response)

    assert exc_info.value.message == message
    assert exc_info.value.metadata == {"values": "default-src 'self', script-src 'self'"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "validator",
    [csp_base_uri_missing, csp_report_only_base_uri_missing, csp_child_src_missing, csp_report_only_child_src_missing],
)
async def test_csp_directive_missing_no_csp_header(validator: Validator):
    response = Response(200)

    message = await validator(response)

    assert message is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,validator,message",
    [
        ("content-security-policy", csp_base_uri_missing, "Content-Security-Policy (CSP) base-uri is missing"),
        (
            "content-security-policy-report-only",
            csp_report_only_base_uri_missing,
            "Content-Security-Policy-Report-Only (CSP) base-uri is missing",
        ),
        ("content-security-policy", csp_child_src_missing, "Content-Security-Policy (CSP) child-src is missing"),
        (
            "content-security-policy-report-only",
            csp_report_only_child_src_missing,
            "Content-Security-Policy-Report-Only (CSP) child-src is missing",
        ),
    ],
)
async def test_csp_directive_missing_absent(header: str, validator: Validator, message: str):
    response = Response(200, headers={header: "foo"})

    with pytest.raises(ValidationError) as exc_info:
        await validator(response)

    assert exc_info.value.message == message
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,value,validator,message",
    [
        (
            "content-security-policy",
            "base-uri 'none'",
            csp_base_uri_missing,
            "Content-Security-Policy (CSP) base-uri is present",
        ),
        (
            "content-security-policy-report-only",
            "base-uri 'none'",
            csp_report_only_base_uri_missing,
            "Content-Security-Policy-Report-Only (CSP) base-uri is present",
        ),
        (
            "content-security-policy",
            "child-src 'self'",
            csp_child_src_missing,
            "Content-Security-Policy (CSP) child-src is present",
        ),
        (
            "content-security-policy-report-only",
            "child-src 'self'",
            csp_report_only_child_src_missing,
            "Content-Security-Policy-Report-Only (CSP) child-src is present",
        ),
    ],
)
async def test_csp_directive_missing_present(header: str, value: str, validator: Validator, message: str):
    response = Response(200, headers={header: value})

    assert await validator(response) == message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,validator,message",
    [
        (
            "content-security-policy",
            csp_child_src_missing,
            "Content-Security-Policy (CSP) child-src is present",
        ),
        (
            "content-security-policy-report-only",
            csp_report_only_child_src_missing,
            "Content-Security-Policy-Report-Only (CSP) child-src is present",
        ),
    ],
)
async def test_csp_directive_missing_default_src_fallback(header: str, validator: Validator, message: str):
    response = Response(200, headers={header: "default-src 'self'"})

    assert await validator(response) == message


@pytest.mark.asyncio
@pytest.mark.parametrize("validator", [csp_child_src_unrestricted, csp_report_only_child_src_unrestricted])
async def test_csp_directive_unrestricted_no_csp_header(validator: Validator):
    response = Response(200)

    message = await validator(response)

    assert message is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,validator",
    [
        ("content-security-policy", csp_child_src_unrestricted),
        ("content-security-policy-report-only", csp_report_only_child_src_unrestricted),
    ],
)
async def test_csp_directive_unrestricted_absent(header: str, validator: Validator):
    response = Response(200, headers={header: "foo"})

    message = await validator(response)

    assert message is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,value,validator,message",
    [
        (
            "content-security-policy",
            "child-src 'self'",
            csp_child_src_unrestricted,
            "Content-Security-Policy (CSP) child-src is restricted",
        ),
        (
            "content-security-policy-report-only",
            "child-src 'self'",
            csp_report_only_child_src_unrestricted,
            "Content-Security-Policy-Report-Only (CSP) child-src is restricted",
        ),
    ],
)
async def test_csp_directive_unrestricted_restricted(header: str, value: str, validator: Validator, message: str):
    response = Response(200, headers={header: value})

    assert await validator(response) == message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,validator,message",
    [
        (
            "content-security-policy",
            csp_child_src_unrestricted,
            "Content-Security-Policy (CSP) child-src is restricted",
        ),
        (
            "content-security-policy-report-only",
            csp_report_only_child_src_unrestricted,
            "Content-Security-Policy-Report-Only (CSP) child-src is restricted",
        ),
    ],
)
async def test_csp_directive_unrestricted_restricted_default_src_fallback(
    header: str, validator: Validator, message: str
):
    response = Response(200, headers={header: "default-src 'self'"})

    assert await validator(response) == message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,value,validator,message",
    [
        (
            "content-security-policy",
            "child-src *",
            csp_child_src_unrestricted,
            "Content-Security-Policy (CSP) child-src is unrestricted",
        ),
        (
            "content-security-policy-report-only",
            "child-src *",
            csp_report_only_child_src_unrestricted,
            "Content-Security-Policy-Report-Only (CSP) child-src is unrestricted",
        ),
    ],
)
async def test_csp_directive_unrestricted_unrestricted(header: str, value: str, validator: Validator, message: str):
    response = Response(200, headers={header: value})

    with pytest.raises(ValidationError) as exc_info:
        await validator(response)

    assert exc_info.value.message == message
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,value,validator,message",
    [
        (
            "content-security-policy",
            "default-src https:",
            csp_child_src_unrestricted,
            "Content-Security-Policy (CSP) child-src is unrestricted",
        ),
        (
            "content-security-policy-report-only",
            "default-src https:",
            csp_report_only_child_src_unrestricted,
            "Content-Security-Policy-Report-Only (CSP) child-src is unrestricted",
        ),
    ],
)
async def test_csp_directive_unrestricted_unrestricted_default_src_fallback(
    header: str, value: str, validator: Validator, message: str
):
    response = Response(200, headers={header: value})

    with pytest.raises(ValidationError) as exc_info:
        await validator(response)

    assert exc_info.value.message == message
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "validator", [csp_block_all_mixed_content_deprecated, csp_report_only_block_all_mixed_content_deprecated]
)
async def test_csp_directive_deprecated_no_csp_header(validator: Validator):
    response = Response(200)

    message = await validator(response)

    assert message is None


@pytest.mark.parametrize(
    "header,validator,message",
    [
        (
            "content-security-policy",
            csp_block_all_mixed_content_deprecated,
            "Content-Security-Policy (CSP) block-all-mixed-content is deprecated",
        ),
        (
            "content-security-policy-report-only",
            csp_report_only_block_all_mixed_content_deprecated,
            "Content-Security-Policy-Report-Only (CSP) block-all-mixed-content is deprecated",
        ),
    ],
)
@pytest.mark.asyncio
async def test_csp_directive_deprecated_present(header: str, validator: Validator, message: str):
    response = Response(200, headers={header: "block-all-mixed-content"})

    with pytest.raises(ValidationError) as exc_info:
        await validator(response)

    assert exc_info.value.message == message
    assert exc_info.value.metadata == {}


@pytest.mark.parametrize(
    "header,validator,message",
    [
        (
            "content-security-policy",
            csp_block_all_mixed_content_deprecated,
            "Content-Security-Policy (CSP) block-all-mixed-content is absent",
        ),
        (
            "content-security-policy-report-only",
            csp_report_only_block_all_mixed_content_deprecated,
            "Content-Security-Policy-Report-Only (CSP) block-all-mixed-content is absent",
        ),
    ],
)
@pytest.mark.asyncio
async def test_csp_directive_deprecated_absent(header: str, validator: Validator, message: str):
    response = Response(200, headers={header: "foo"})

    assert await validator(response) == message


# REFACTOR POINT ENDS HERE


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
async def test_csp_img_src_unrestricted_no_csp():
    response = Response(200)

    message = await csp_img_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_img_src_unrestricted_no_img_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "base-uri 'self'"})

    message = await csp_img_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_img_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy": "img-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_img_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) img-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_img_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_img_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) img-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_img_src_unrestricted_clean_img_src():
    response = Response(200, headers={"content-security-policy": "img-src 'self'"})

    message = await csp_img_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) img-src is restricted"


@pytest.mark.asyncio
async def test_csp_font_src_unrestricted_no_csp():
    response = Response(200)

    message = await csp_font_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_font_src_unrestricted_no_font_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "base-uri 'self'"})

    message = await csp_font_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_font_src_unrestricted_wildcard_http():
    response = Response(200, headers={"content-security-policy": "font-src http:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_font_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) font-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_font_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_font_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) font-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_font_src_unrestricted_clean_font_src():
    response = Response(200, headers={"content-security-policy": "font-src https://fonts.example"})

    message = await csp_font_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) font-src is restricted"


@pytest.mark.asyncio
async def test_csp_worker_src_unrestricted_no_csp():
    response = Response(200)

    message = await csp_worker_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_worker_src_unrestricted_no_worker_src_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "base-uri 'self'"})

    message = await csp_worker_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_worker_src_unrestricted_wildcard_via_script_src():
    response = Response(200, headers={"content-security-policy": "script-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_worker_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) worker-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_worker_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_worker_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) worker-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_worker_src_unrestricted_clean_worker_src():
    response = Response(200, headers={"content-security-policy": "worker-src 'self'"})

    message = await csp_worker_src_unrestricted(response)

    assert message == "Content-Security-Policy (CSP) worker-src is restricted"


@pytest.mark.asyncio
async def test_csp_img_src_missing_no_csp():
    response = Response(200)

    message = await csp_img_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_img_src_missing_no_img_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "base-uri 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_img_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) img-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_img_src_missing_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    message = await csp_img_src_missing(response)

    assert message == "Content-Security-Policy (CSP) img-src is present"


@pytest.mark.asyncio
async def test_csp_font_src_missing_no_csp():
    response = Response(200)

    message = await csp_font_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_font_src_missing_no_font_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "base-uri 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_font_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) font-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_font_src_missing_present():
    response = Response(200, headers={"content-security-policy": "font-src 'self'"})

    message = await csp_font_src_missing(response)

    assert message == "Content-Security-Policy (CSP) font-src is present"


@pytest.mark.asyncio
async def test_csp_worker_src_missing_no_csp():
    response = Response(200)

    message = await csp_worker_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_worker_src_missing_no_worker_src_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy": "base-uri 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_worker_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) worker-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_worker_src_missing_present_via_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    message = await csp_worker_src_missing(response)

    assert message == "Content-Security-Policy (CSP) worker-src is present"


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
async def test_csp_ro_img_src_unrestricted_no_header():
    response = Response(200)

    message = await csp_ro_img_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_img_src_unrestricted_no_img_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "base-uri 'self'"})

    message = await csp_ro_img_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_img_src_unrestricted_wildcard_star():
    response = Response(200, headers={"content-security-policy-report-only": "img-src *"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_img_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) img-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_img_src_unrestricted_clean_img_src():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    message = await csp_ro_img_src_unrestricted(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) img-src is restricted"


@pytest.mark.asyncio
async def test_csp_ro_font_src_unrestricted_no_header():
    response = Response(200)

    message = await csp_ro_font_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_font_src_unrestricted_no_font_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "base-uri 'self'"})

    message = await csp_ro_font_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_font_src_unrestricted_wildcard_via_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "default-src https:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_font_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) font-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_font_src_unrestricted_clean_font_src():
    response = Response(200, headers={"content-security-policy-report-only": "font-src https://fonts.example"})

    message = await csp_ro_font_src_unrestricted(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) font-src is restricted"


@pytest.mark.asyncio
async def test_csp_ro_worker_src_unrestricted_no_header():
    response = Response(200)

    message = await csp_ro_worker_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_worker_src_unrestricted_no_worker_src_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "base-uri 'self'"})

    message = await csp_ro_worker_src_unrestricted(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_worker_src_unrestricted_wildcard_via_script_src():
    response = Response(200, headers={"content-security-policy-report-only": "script-src http:"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_worker_src_unrestricted(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) worker-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_worker_src_unrestricted_clean_worker_src():
    response = Response(200, headers={"content-security-policy-report-only": "worker-src 'self'"})

    message = await csp_ro_worker_src_unrestricted(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) worker-src is restricted"


@pytest.mark.asyncio
async def test_csp_ro_img_src_missing_no_header():
    response = Response(200)

    message = await csp_ro_img_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_img_src_missing_no_img_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "base-uri 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_img_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) img-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_img_src_missing_present():
    response = Response(200, headers={"content-security-policy-report-only": "img-src 'self'"})

    message = await csp_ro_img_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) img-src is present"


@pytest.mark.asyncio
async def test_csp_ro_font_src_missing_no_header():
    response = Response(200)

    message = await csp_ro_font_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_font_src_missing_no_font_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "base-uri 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_font_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) font-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_font_src_missing_present_via_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "default-src 'self'"})

    message = await csp_ro_font_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) font-src is present"


@pytest.mark.asyncio
async def test_csp_ro_worker_src_missing_no_header():
    response = Response(200)

    message = await csp_ro_worker_src_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_csp_ro_worker_src_missing_no_worker_src_no_script_src_no_default_src():
    response = Response(200, headers={"content-security-policy-report-only": "base-uri 'self'"})

    with pytest.raises(ValidationError) as exc_info:
        await csp_ro_worker_src_missing(response)

    assert exc_info.value.message == "Content-Security-Policy-Report-Only (CSP) worker-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_ro_worker_src_missing_present():
    response = Response(200, headers={"content-security-policy-report-only": "worker-src 'self'"})

    message = await csp_ro_worker_src_missing(response)

    assert message == "Content-Security-Policy-Report-Only (CSP) worker-src is present"
