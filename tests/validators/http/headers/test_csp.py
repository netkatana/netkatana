import pytest
from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.validators.http.headers.csp import (
    csp_block_all_mixed_content_deprecated,
    csp_child_src_missing,
    csp_child_src_source_insecure_scheme,
    csp_child_src_source_ip,
    csp_child_src_unrestricted,
    csp_connect_src_source_insecure_scheme,
    csp_connect_src_source_ip,
    csp_deprecated_directive,
    csp_duplicated,
    csp_form_action_hash_invalid,
    csp_form_action_missing,
    csp_form_action_nonce_invalid,
    csp_form_action_source_insecure_scheme,
    csp_form_action_source_ip,
    csp_frame_ancestors_unsafe,
    csp_frame_src_missing,
    csp_img_src_source_insecure_scheme,
    csp_img_src_source_ip,
    csp_invalid_directive,
    csp_missing,
    csp_object_src_unsafe,
    csp_reporting_endpoint_missing,
    csp_require_trusted_types_for_invalid,
    csp_require_trusted_types_for_missing,
    csp_sandbox_allow_same_origin_and_scripts,
    csp_sandbox_invalid,
    csp_sandbox_missing,
    csp_script_src_attr_missing,
    csp_script_src_attr_nonce_invalid,
    csp_script_src_elem_unsafe_inline,
    csp_script_src_hash_invalid,
    csp_script_src_nonce_invalid,
    csp_script_src_source_insecure_scheme,
    csp_script_src_source_ip,
    csp_style_src_attr_missing,
    csp_style_src_elem_hash_invalid,
    csp_style_src_elem_unsafe_inline,
    csp_style_src_hash_invalid,
    csp_style_src_nonce_invalid,
    csp_style_src_source_insecure_scheme,
    csp_style_src_source_ip,
    csp_trusted_types_allow_duplicates,
    csp_trusted_types_invalid,
    csp_trusted_types_missing,
    csp_unknown_directive,
    csp_unsafe_eval,
    csp_unsafe_inline,
    csp_upgrade_insecure_requests_missing,
    csp_worker_src_missing,
    csp_worker_src_source_insecure_scheme,
    csp_worker_src_source_ip,
    csp_worker_src_unrestricted,
)


@pytest.mark.asyncio
async def test_csp_missing_missing():
    with pytest.raises(ValidationError) as exc_info:
        await csp_missing(Response(200))

    assert exc_info.value.message == "Content-Security-Policy (CSP) missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_csp_missing_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    assert await csp_missing(response) == "Content-Security-Policy (CSP) present"


@pytest.mark.asyncio
async def test_duplicated_header_validator_header_absent():
    assert await csp_duplicated(Response(200)) is None


@pytest.mark.asyncio
async def test_duplicated_header_validator_single_header():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    assert await csp_duplicated(response) == "Content-Security-Policy (CSP) header is not duplicated"


@pytest.mark.asyncio
async def test_duplicated_header_validator_duplicated_header():
    response = Response(
        200,
        headers=[
            ("content-security-policy", "default-src 'self'"),
            ("content-security-policy", "script-src 'self'"),
        ],
    )

    with pytest.raises(ValidationError) as exc_info:
        await csp_duplicated(response)

    assert exc_info.value.message == "Content-Security-Policy (CSP) header is duplicated"
    assert exc_info.value.metadata == {"values": "default-src 'self', script-src 'self'"}


@pytest.mark.asyncio
async def test_missing_directive_with_fallback_header_absent():
    assert await csp_child_src_missing(Response(200)) is None


@pytest.mark.asyncio
async def test_missing_directive_with_fallback_directive_absent():
    with pytest.raises(ValidationError) as exc_info:
        await csp_child_src_missing(Response(200, headers={"content-security-policy": "foo"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) child-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_missing_directive_with_fallback_directive_present():
    response = Response(200, headers={"content-security-policy": "child-src 'self'"})

    assert await csp_child_src_missing(response) == "Content-Security-Policy (CSP) child-src is present"


@pytest.mark.asyncio
async def test_missing_directive_with_fallback_default_src_present():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    assert await csp_child_src_missing(response) == "Content-Security-Policy (CSP) child-src is present"


@pytest.mark.asyncio
async def test_missing_directive_without_fallback_header_absent():
    assert await csp_form_action_missing(Response(200)) is None


@pytest.mark.asyncio
async def test_missing_directive_without_fallback_directive_absent():
    with pytest.raises(ValidationError) as exc_info:
        await csp_form_action_missing(Response(200, headers={"content-security-policy": "foo"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) form-action is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_missing_directive_without_fallback_directive_present():
    response = Response(200, headers={"content-security-policy": "form-action 'self'"})

    assert await csp_form_action_missing(response) == "Content-Security-Policy (CSP) form-action is present"


@pytest.mark.asyncio
async def test_missing_directive_without_fallback_default_src_ignored():
    with pytest.raises(ValidationError) as exc_info:
        await csp_form_action_missing(Response(200, headers={"content-security-policy": "default-src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) form-action is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_unrestricted_directive_header_absent():
    assert await csp_child_src_unrestricted(Response(200)) is None


@pytest.mark.asyncio
async def test_unrestricted_directive_directive_absent():
    assert await csp_child_src_unrestricted(Response(200, headers={"content-security-policy": "foo"})) is None


@pytest.mark.asyncio
async def test_unrestricted_directive_restricted_directive():
    response = Response(200, headers={"content-security-policy": "child-src 'self'"})

    assert await csp_child_src_unrestricted(response) == "Content-Security-Policy (CSP) child-src is restricted"


@pytest.mark.asyncio
async def test_unrestricted_directive_restricted_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    assert await csp_child_src_unrestricted(response) == "Content-Security-Policy (CSP) child-src is restricted"


@pytest.mark.asyncio
async def test_unrestricted_directive_unrestricted_directive():
    with pytest.raises(ValidationError) as exc_info:
        await csp_child_src_unrestricted(Response(200, headers={"content-security-policy": "child-src *"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) child-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_unrestricted_directive_unrestricted_default_src_fallback():
    with pytest.raises(ValidationError) as exc_info:
        await csp_child_src_unrestricted(Response(200, headers={"content-security-policy": "default-src https:"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) child-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_nonce_invalid_directive_header_absent():
    assert await csp_form_action_nonce_invalid(Response(200)) is None


@pytest.mark.asyncio
async def test_nonce_invalid_directive_directive_absent():
    assert await csp_form_action_nonce_invalid(Response(200, headers={"content-security-policy": "foo"})) is None


@pytest.mark.asyncio
async def test_nonce_invalid_directive_valid_nonce():
    response = Response(200, headers={"content-security-policy": "form-action 'nonce-abc123=='"})

    assert (
        await csp_form_action_nonce_invalid(response)
        == "Content-Security-Policy (CSP) form-action nonce sources are valid"
    )


@pytest.mark.asyncio
async def test_nonce_invalid_directive_invalid_nonce():
    with pytest.raises(ValidationError) as exc_info:
        await csp_form_action_nonce_invalid(Response(200, headers={"content-security-policy": "form-action 'nonce-'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) form-action contains an invalid nonce source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_nonce_invalid_directive_default_src_ignored():
    response = Response(200, headers={"content-security-policy": "default-src 'nonce-abc123=='"})

    assert await csp_form_action_nonce_invalid(response) is None


@pytest.mark.asyncio
async def test_hash_invalid_directive_header_absent():
    assert await csp_form_action_hash_invalid(Response(200)) is None


@pytest.mark.asyncio
async def test_hash_invalid_directive_directive_absent():
    assert await csp_form_action_hash_invalid(Response(200, headers={"content-security-policy": "foo"})) is None


@pytest.mark.asyncio
async def test_hash_invalid_directive_valid_hash():
    response = Response(200, headers={"content-security-policy": "form-action 'sha256-abc123=='"})

    assert (
        await csp_form_action_hash_invalid(response)
        == "Content-Security-Policy (CSP) form-action hash sources are valid"
    )


@pytest.mark.asyncio
async def test_hash_invalid_directive_invalid_hash():
    with pytest.raises(ValidationError) as exc_info:
        await csp_form_action_hash_invalid(
            Response(200, headers={"content-security-policy": "form-action 'sha1-abc123=='"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) form-action contains an invalid hash source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_hash_invalid_directive_default_src_ignored():
    response = Response(200, headers={"content-security-policy": "default-src 'sha256-abc123=='"})

    assert await csp_form_action_hash_invalid(response) is None


@pytest.mark.asyncio
async def test_insecure_scheme_directive_header_absent():
    assert await csp_child_src_source_insecure_scheme(Response(200)) is None


@pytest.mark.asyncio
async def test_insecure_scheme_directive_directive_absent():
    assert await csp_child_src_source_insecure_scheme(Response(200, headers={"content-security-policy": "foo"})) is None


@pytest.mark.asyncio
async def test_insecure_scheme_directive_secure_source():
    response = Response(200, headers={"content-security-policy": "child-src https://example.com"})

    assert (
        await csp_child_src_source_insecure_scheme(response)
        == "Content-Security-Policy (CSP) child-src sources do not use insecure schemes"
    )


@pytest.mark.asyncio
async def test_insecure_scheme_directive_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src https://example.com"})

    assert (
        await csp_child_src_source_insecure_scheme(response)
        == "Content-Security-Policy (CSP) child-src sources do not use insecure schemes"
    )


@pytest.mark.asyncio
async def test_insecure_scheme_directive_insecure_source():
    with pytest.raises(ValidationError) as exc_info:
        await csp_child_src_source_insecure_scheme(
            Response(200, headers={"content-security-policy": "child-src http://example.com"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) child-src contains an insecure scheme source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_insecure_scheme_directive_without_fallback_default_src_ignored():
    response = Response(200, headers={"content-security-policy": "default-src http://example.com"})

    assert await csp_form_action_source_insecure_scheme(response) is None


@pytest.mark.asyncio
async def test_ip_source_directive_header_absent():
    assert await csp_child_src_source_ip(Response(200)) is None


@pytest.mark.asyncio
async def test_ip_source_directive_directive_absent():
    assert await csp_child_src_source_ip(Response(200, headers={"content-security-policy": "foo"})) is None


@pytest.mark.asyncio
async def test_ip_source_directive_hostname_source():
    response = Response(200, headers={"content-security-policy": "child-src https://example.com"})

    assert (
        await csp_child_src_source_ip(response)
        == "Content-Security-Policy (CSP) child-src sources do not use IP addresses"
    )


@pytest.mark.asyncio
async def test_ip_source_directive_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self' https://example.com"})

    assert (
        await csp_child_src_source_ip(response)
        == "Content-Security-Policy (CSP) child-src sources do not use IP addresses"
    )


@pytest.mark.asyncio
async def test_ip_source_directive_url_ip():
    with pytest.raises(ValidationError) as exc_info:
        await csp_child_src_source_ip(Response(200, headers={"content-security-policy": "child-src https://127.0.0.1"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) child-src contains an IP source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_ip_source_directive_bare_ip():
    with pytest.raises(ValidationError) as exc_info:
        await csp_child_src_source_ip(Response(200, headers={"content-security-policy": "child-src 127.0.0.1"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) child-src contains an IP source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_ip_source_directive_without_fallback_default_src_ignored():
    response = Response(200, headers={"content-security-policy": "default-src https://127.0.0.1"})

    assert await csp_form_action_source_ip(response) is None


@pytest.mark.asyncio
async def test_deprecated_directive_header_absent():
    assert await csp_block_all_mixed_content_deprecated(Response(200)) is None


@pytest.mark.asyncio
async def test_deprecated_directive_absent():
    response = Response(200, headers={"content-security-policy": "foo"})

    assert (
        await csp_block_all_mixed_content_deprecated(response)
        == "Content-Security-Policy (CSP) block-all-mixed-content is absent"
    )


@pytest.mark.asyncio
async def test_deprecated_directive_present():
    with pytest.raises(ValidationError) as exc_info:
        await csp_block_all_mixed_content_deprecated(
            Response(200, headers={"content-security-policy": "block-all-mixed-content"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) block-all-mixed-content is deprecated"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_unsafe_inline_header_absent():
    assert await csp_unsafe_inline(Response(200)) is None


@pytest.mark.asyncio
async def test_unsafe_inline_no_effective_script_source():
    assert await csp_unsafe_inline(Response(200, headers={"content-security-policy": "img-src 'self'"})) is None


@pytest.mark.asyncio
async def test_unsafe_inline_clean_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    assert (
        await csp_unsafe_inline(response) == "Content-Security-Policy (CSP) script-src does not contain 'unsafe-inline'"
    )


@pytest.mark.asyncio
async def test_unsafe_inline_neutralized_by_nonce():
    response = Response(200, headers={"content-security-policy": "script-src 'nonce-abc123' 'unsafe-inline'"})

    assert (
        await csp_unsafe_inline(response)
        == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"
    )


@pytest.mark.asyncio
async def test_unsafe_inline_neutralized_by_hash():
    response = Response(200, headers={"content-security-policy": "script-src 'sha256-abc123=' 'unsafe-inline'"})

    assert (
        await csp_unsafe_inline(response)
        == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"
    )


@pytest.mark.asyncio
async def test_unsafe_inline_neutralized_by_strict_dynamic():
    response = Response(
        200,
        headers={"content-security-policy": "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline'"},
    )

    assert (
        await csp_unsafe_inline(response)
        == "Content-Security-Policy (CSP) 'unsafe-inline' is neutralized by nonce or hash"
    )


@pytest.mark.asyncio
async def test_unsafe_inline_in_script_src():
    with pytest.raises(ValidationError) as exc_info:
        await csp_unsafe_inline(Response(200, headers={"content-security-policy": "script-src 'self' 'unsafe-inline'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_unsafe_inline_via_default_src_fallback():
    with pytest.raises(ValidationError) as exc_info:
        await csp_unsafe_inline(
            Response(200, headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_unsafe_eval_header_absent():
    assert await csp_unsafe_eval(Response(200)) is None


@pytest.mark.asyncio
async def test_unsafe_eval_no_effective_script_source():
    assert await csp_unsafe_eval(Response(200, headers={"content-security-policy": "img-src 'self'"})) is None


@pytest.mark.asyncio
async def test_unsafe_eval_clean_script_src():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    assert await csp_unsafe_eval(response) == "Content-Security-Policy (CSP) script-src does not contain 'unsafe-eval'"


@pytest.mark.asyncio
async def test_unsafe_eval_present():
    with pytest.raises(ValidationError) as exc_info:
        await csp_unsafe_eval(Response(200, headers={"content-security-policy": "script-src 'self' 'unsafe-eval'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains 'unsafe-eval'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_exact_value_validator_header_absent():
    assert await csp_object_src_unsafe(Response(200)) is None


@pytest.mark.asyncio
async def test_exact_value_validator_exact_value_present():
    response = Response(200, headers={"content-security-policy": "object-src 'none'"})

    assert await csp_object_src_unsafe(response) == "Content-Security-Policy (CSP) object-src is restricted to 'none'"


@pytest.mark.asyncio
async def test_exact_value_validator_other_value_present():
    with pytest.raises(ValidationError) as exc_info:
        await csp_object_src_unsafe(Response(200, headers={"content-security-policy": "object-src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) object-src is not restricted to 'none'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_frame_ancestors_unsafe_header_absent():
    assert await csp_frame_ancestors_unsafe(Response(200)) is None


@pytest.mark.asyncio
async def test_frame_ancestors_unsafe_none_allowed():
    response = Response(200, headers={"content-security-policy": "frame-ancestors 'none'"})

    assert (
        await csp_frame_ancestors_unsafe(response)
        == "Content-Security-Policy (CSP) frame-ancestors is restricted to 'none' or 'self'"
    )


@pytest.mark.asyncio
async def test_frame_ancestors_unsafe_self_allowed():
    response = Response(200, headers={"content-security-policy": "frame-ancestors 'self'"})

    assert (
        await csp_frame_ancestors_unsafe(response)
        == "Content-Security-Policy (CSP) frame-ancestors is restricted to 'none' or 'self'"
    )


@pytest.mark.asyncio
async def test_frame_ancestors_unsafe_other_origin_present():
    with pytest.raises(ValidationError) as exc_info:
        await csp_frame_ancestors_unsafe(
            Response(200, headers={"content-security-policy": "frame-ancestors https://partner.example"})
        )

    assert (
        exc_info.value.message == "Content-Security-Policy (CSP) frame-ancestors allows origins beyond 'none' or 'self'"
    )
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_frame_src_missing_child_src_fallback():
    response = Response(200, headers={"content-security-policy": "child-src 'self'"})

    assert await csp_frame_src_missing(response) == "Content-Security-Policy (CSP) frame-src is present"


@pytest.mark.asyncio
async def test_frame_src_missing_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    assert await csp_frame_src_missing(response) == "Content-Security-Policy (CSP) frame-src is present"


@pytest.mark.asyncio
async def test_frame_src_missing_no_effective_fallback():
    with pytest.raises(ValidationError) as exc_info:
        await csp_frame_src_missing(Response(200, headers={"content-security-policy": "img-src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) frame-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_script_src_attr_missing_script_src_fallback():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    assert await csp_script_src_attr_missing(response) == "Content-Security-Policy (CSP) script-src-attr is present"


@pytest.mark.asyncio
async def test_script_src_nonce_invalid_rejects_invalid_nonce():
    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_nonce_invalid(Response(200, headers={"content-security-policy": "script-src 'nonce-'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains an invalid nonce source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_script_src_hash_invalid_rejects_invalid_hash():
    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_hash_invalid(
            Response(200, headers={"content-security-policy": "script-src 'sha1-abc123=='"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains an invalid hash source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_script_src_source_insecure_scheme_uses_default_src_fallback():
    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_source_insecure_scheme(
            Response(200, headers={"content-security-policy": "default-src http://example.com"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains an insecure scheme source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_script_src_source_ip_rejects_ip_source():
    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_source_ip(Response(200, headers={"content-security-policy": "script-src 127.0.0.1"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src contains an IP source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_script_src_attr_nonce_invalid_rejects_invalid_nonce():
    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_attr_nonce_invalid(
            Response(200, headers={"content-security-policy": "script-src-attr 'nonce-'"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src-attr contains an invalid nonce source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_script_src_elem_unsafe_inline_rejects_unsafe_inline():
    with pytest.raises(ValidationError) as exc_info:
        await csp_script_src_elem_unsafe_inline(
            Response(200, headers={"content-security-policy": "script-src-elem 'self' 'unsafe-inline'"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) script-src-elem contains 'unsafe-inline'"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_style_src_attr_missing_style_src_fallback():
    response = Response(200, headers={"content-security-policy": "style-src 'self'"})

    assert await csp_style_src_attr_missing(response) == "Content-Security-Policy (CSP) style-src-attr is present"


@pytest.mark.asyncio
async def test_style_src_nonce_invalid_rejects_invalid_nonce():
    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_nonce_invalid(Response(200, headers={"content-security-policy": "style-src 'nonce-'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src contains an invalid nonce source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_style_src_hash_invalid_rejects_invalid_hash():
    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_hash_invalid(
            Response(200, headers={"content-security-policy": "style-src 'sha1-abc123=='"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src contains an invalid hash source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_style_src_source_insecure_scheme_rejects_http_source():
    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_source_insecure_scheme(
            Response(200, headers={"content-security-policy": "style-src http://example.com"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src contains an insecure scheme source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_style_src_source_ip_rejects_ip_source():
    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_source_ip(Response(200, headers={"content-security-policy": "style-src https://127.0.0.1"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src contains an IP source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_style_src_elem_hash_invalid_rejects_invalid_hash():
    with pytest.raises(ValidationError) as exc_info:
        await csp_style_src_elem_hash_invalid(
            Response(200, headers={"content-security-policy": "style-src-elem 'sha1-abc123=='"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) style-src-elem contains an invalid hash source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_style_src_elem_unsafe_inline_neutralized_by_nonce():
    response = Response(
        200,
        headers={"content-security-policy": "style-src-elem 'nonce-abc123' 'unsafe-inline'"},
    )

    assert (
        await csp_style_src_elem_unsafe_inline(response)
        == "Content-Security-Policy (CSP) style-src-elem 'unsafe-inline' is neutralized by nonce or hash"
    )


@pytest.mark.asyncio
async def test_reporting_endpoint_missing_header_absent():
    assert await csp_reporting_endpoint_missing(Response(200)) is None


@pytest.mark.asyncio
async def test_reporting_endpoint_missing_report_to_present():
    response = Response(200, headers={"content-security-policy": "report-to endpoint"})

    assert (
        await csp_reporting_endpoint_missing(response) == "Content-Security-Policy (CSP) reporting endpoint is present"
    )


@pytest.mark.asyncio
async def test_reporting_endpoint_missing_report_uri_present():
    response = Response(200, headers={"content-security-policy": "report-uri /csp-report"})

    assert (
        await csp_reporting_endpoint_missing(response) == "Content-Security-Policy (CSP) reporting endpoint is present"
    )


@pytest.mark.asyncio
async def test_reporting_endpoint_missing_no_reporting_directive():
    with pytest.raises(ValidationError) as exc_info:
        await csp_reporting_endpoint_missing(Response(200, headers={"content-security-policy": "default-src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) reporting endpoint is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_presence_directive_header_absent():
    assert await csp_require_trusted_types_for_missing(Response(200)) is None


@pytest.mark.asyncio
async def test_presence_directive_present():
    response = Response(200, headers={"content-security-policy": "require-trusted-types-for 'script'"})

    assert (
        await csp_require_trusted_types_for_missing(response)
        == "Content-Security-Policy (CSP) require-trusted-types-for is present"
    )


@pytest.mark.asyncio
async def test_presence_directive_missing():
    with pytest.raises(ValidationError) as exc_info:
        await csp_require_trusted_types_for_missing(
            Response(200, headers={"content-security-policy": "default-src 'self'"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) require-trusted-types-for is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_require_trusted_types_for_invalid_rejects_non_script_value():
    with pytest.raises(ValidationError) as exc_info:
        await csp_require_trusted_types_for_invalid(
            Response(200, headers={"content-security-policy": "require-trusted-types-for 'style'"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) require-trusted-types-for value is invalid"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_require_trusted_types_for_invalid_accepts_script():
    response = Response(200, headers={"content-security-policy": "require-trusted-types-for 'script'"})

    assert (
        await csp_require_trusted_types_for_invalid(response)
        == "Content-Security-Policy (CSP) require-trusted-types-for value is valid"
    )


@pytest.mark.asyncio
async def test_trusted_types_missing_present():
    response = Response(200, headers={"content-security-policy": "trusted-types default"})

    assert await csp_trusted_types_missing(response) == "Content-Security-Policy (CSP) trusted-types is present"


@pytest.mark.asyncio
async def test_trusted_types_invalid_rejects_none_with_other_value():
    with pytest.raises(ValidationError) as exc_info:
        await csp_trusted_types_invalid(
            Response(200, headers={"content-security-policy": "trusted-types 'none' default"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) trusted-types value is invalid"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_trusted_types_allow_duplicates_rejects_keyword():
    with pytest.raises(ValidationError) as exc_info:
        await csp_trusted_types_allow_duplicates(
            Response(200, headers={"content-security-policy": "trusted-types default 'allow-duplicates'"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) trusted-types allows duplicate policy names"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_upgrade_insecure_requests_missing_present():
    response = Response(200, headers={"content-security-policy": "upgrade-insecure-requests"})

    assert (
        await csp_upgrade_insecure_requests_missing(response)
        == "Content-Security-Policy (CSP) upgrade-insecure-requests is present"
    )


@pytest.mark.asyncio
async def test_invalid_directive_header_absent():
    assert await csp_invalid_directive(Response(200)) is None


@pytest.mark.asyncio
async def test_invalid_directive_valid_names():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; script-src 'self'"})

    assert (
        await csp_invalid_directive(response) == "Content-Security-Policy (CSP) directive names are syntactically valid"
    )


@pytest.mark.asyncio
async def test_invalid_directive_invalid_name():
    with pytest.raises(ValidationError) as exc_info:
        await csp_invalid_directive(Response(200, headers={"content-security-policy": "script_src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) contains an invalid directive name"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_unknown_directive_known_names():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; worker-src 'self'"})

    assert await csp_unknown_directive(response) == "Content-Security-Policy (CSP) directives are recognized"


@pytest.mark.asyncio
async def test_unknown_directive_unknown_name():
    with pytest.raises(ValidationError) as exc_info:
        await csp_unknown_directive(Response(200, headers={"content-security-policy": "future-src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) contains an unknown directive"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_deprecated_directive_global_clean_policy():
    response = Response(200, headers={"content-security-policy": "default-src 'self'; script-src 'self'"})

    assert (
        await csp_deprecated_directive(response)
        == "Content-Security-Policy (CSP) does not contain deprecated directives"
    )


@pytest.mark.asyncio
async def test_deprecated_directive_global_deprecated_present():
    with pytest.raises(ValidationError) as exc_info:
        await csp_deprecated_directive(Response(200, headers={"content-security-policy": "prefetch-src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) contains a deprecated directive"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_sandbox_missing_header_absent():
    assert await csp_sandbox_missing(Response(200)) is None


@pytest.mark.asyncio
async def test_sandbox_missing_present():
    response = Response(200, headers={"content-security-policy": "sandbox allow-scripts"})

    assert await csp_sandbox_missing(response) == "Content-Security-Policy (CSP) sandbox is present"


@pytest.mark.asyncio
async def test_sandbox_missing_absent():
    with pytest.raises(ValidationError) as exc_info:
        await csp_sandbox_missing(Response(200, headers={"content-security-policy": "default-src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) sandbox is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_sandbox_invalid_rejects_unknown_token():
    with pytest.raises(ValidationError) as exc_info:
        await csp_sandbox_invalid(Response(200, headers={"content-security-policy": "sandbox allow-lol"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) sandbox contains an invalid token"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_sandbox_allow_same_origin_and_scripts_rejects_unsafe_combination():
    with pytest.raises(ValidationError) as exc_info:
        await csp_sandbox_allow_same_origin_and_scripts(
            Response(200, headers={"content-security-policy": "sandbox allow-scripts allow-same-origin"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) sandbox allows both scripts and same-origin"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_sandbox_allow_same_origin_and_scripts_accepts_single_capability():
    response = Response(200, headers={"content-security-policy": "sandbox allow-scripts"})

    assert (
        await csp_sandbox_allow_same_origin_and_scripts(response)
        == "Content-Security-Policy (CSP) sandbox does not allow both scripts and same-origin"
    )


@pytest.mark.asyncio
async def test_worker_missing_header_absent():
    assert await csp_worker_src_missing(Response(200)) is None


@pytest.mark.asyncio
async def test_worker_missing_no_fallback_directives():
    with pytest.raises(ValidationError) as exc_info:
        await csp_worker_src_missing(Response(200, headers={"content-security-policy": "img-src 'self'"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) worker-src is missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_worker_missing_worker_src_present():
    response = Response(200, headers={"content-security-policy": "worker-src 'self'"})

    assert await csp_worker_src_missing(response) == "Content-Security-Policy (CSP) worker-src is present"


@pytest.mark.asyncio
async def test_worker_missing_script_src_fallback():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    assert await csp_worker_src_missing(response) == "Content-Security-Policy (CSP) worker-src is present"


@pytest.mark.asyncio
async def test_worker_missing_child_src_fallback():
    response = Response(200, headers={"content-security-policy": "child-src 'self'"})

    assert await csp_worker_src_missing(response) == "Content-Security-Policy (CSP) worker-src is present"


@pytest.mark.asyncio
async def test_worker_missing_default_src_fallback():
    response = Response(200, headers={"content-security-policy": "default-src 'self'"})

    assert await csp_worker_src_missing(response) == "Content-Security-Policy (CSP) worker-src is present"


@pytest.mark.asyncio
async def test_worker_unrestricted_worker_src_restricted():
    response = Response(200, headers={"content-security-policy": "worker-src 'self'"})

    assert await csp_worker_src_unrestricted(response) == "Content-Security-Policy (CSP) worker-src is restricted"


@pytest.mark.asyncio
async def test_worker_unrestricted_script_src_fallback_restricted():
    response = Response(200, headers={"content-security-policy": "script-src 'self'"})

    assert await csp_worker_src_unrestricted(response) == "Content-Security-Policy (CSP) worker-src is restricted"


@pytest.mark.asyncio
async def test_worker_unrestricted_child_src_fallback_restricted():
    response = Response(200, headers={"content-security-policy": "child-src 'self'"})

    assert await csp_worker_src_unrestricted(response) == "Content-Security-Policy (CSP) worker-src is restricted"


@pytest.mark.asyncio
async def test_worker_unrestricted_default_src_fallback_unrestricted():
    with pytest.raises(ValidationError) as exc_info:
        await csp_worker_src_unrestricted(Response(200, headers={"content-security-policy": "default-src https:"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) worker-src is unrestricted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_connect_src_source_insecure_scheme_rejects_http_source():
    with pytest.raises(ValidationError) as exc_info:
        await csp_connect_src_source_insecure_scheme(
            Response(200, headers={"content-security-policy": "connect-src http://api.example.com"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src contains an insecure scheme source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_connect_src_source_ip_rejects_ip_source():
    with pytest.raises(ValidationError) as exc_info:
        await csp_connect_src_source_ip(
            Response(200, headers={"content-security-policy": "connect-src https://127.0.0.1"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) connect-src contains an IP source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_img_src_source_insecure_scheme_rejects_http_source():
    with pytest.raises(ValidationError) as exc_info:
        await csp_img_src_source_insecure_scheme(
            Response(200, headers={"content-security-policy": "img-src http://cdn.example.com"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) img-src contains an insecure scheme source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_img_src_source_ip_rejects_ip_source():
    with pytest.raises(ValidationError) as exc_info:
        await csp_img_src_source_ip(Response(200, headers={"content-security-policy": "img-src 127.0.0.1"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) img-src contains an IP source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_worker_src_source_insecure_scheme_uses_script_src_fallback():
    with pytest.raises(ValidationError) as exc_info:
        await csp_worker_src_source_insecure_scheme(
            Response(200, headers={"content-security-policy": "script-src http://cdn.example.com"})
        )

    assert exc_info.value.message == "Content-Security-Policy (CSP) worker-src contains an insecure scheme source"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_worker_src_source_ip_uses_child_src_fallback():
    with pytest.raises(ValidationError) as exc_info:
        await csp_worker_src_source_ip(Response(200, headers={"content-security-policy": "child-src 127.0.0.1"}))

    assert exc_info.value.message == "Content-Security-Policy (CSP) worker-src contains an IP source"
    assert exc_info.value.metadata == {}
