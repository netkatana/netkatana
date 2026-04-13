import pytest
from httpx import Response

from netkatana.exceptions import ValidationError
from netkatana.validators.http.headers.csp import (
    csp_block_all_mixed_content_deprecated,
    csp_child_src_missing,
    csp_child_src_source_insecure_scheme,
    csp_child_src_source_ip,
    csp_child_src_unrestricted,
    csp_duplicated,
    csp_form_action_hash_invalid,
    csp_form_action_missing,
    csp_form_action_nonce_invalid,
    csp_form_action_source_insecure_scheme,
    csp_form_action_source_ip,
    csp_frame_ancestors_unsafe,
    csp_frame_src_missing,
    csp_missing,
    csp_object_src_unsafe,
    csp_unsafe_eval,
    csp_unsafe_inline,
    csp_worker_src_missing,
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
