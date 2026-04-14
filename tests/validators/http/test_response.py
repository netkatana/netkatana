import pytest
from httpx import Request, Response

from netkatana.exceptions import ValidationError
from netkatana.validators.http.response import (
    https_unsupported,
    https_upgrade_redirect_missing,
    redirect_chain_long,
    redirect_chain_mixed_schemes,
    redirect_https_downgrade,
    status_server_error,
)


def _response(
    status_code: int,
    url: str,
    history: list[Response] | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    response = Response(status_code, request=Request("GET", url), headers=headers)
    response.history = history or []
    return response


@pytest.mark.asyncio
async def test_status_server_error_success():
    response = _response(200, "https://example.com")

    message = await status_server_error(response)

    assert message == "Response did not return a server error status"


@pytest.mark.asyncio
async def test_status_server_error_failure():
    response = _response(503, "https://example.com")

    with pytest.raises(ValidationError) as exc_info:
        await status_server_error(response)

    assert exc_info.value.message == "Response returned a server error status"
    assert exc_info.value.metadata == {"status_code": "503"}


@pytest.mark.asyncio
async def test_https_unsupported_success():
    response = _response(200, "https://example.com")

    message = await https_unsupported(response)

    assert message == "HTTPS is supported"


@pytest.mark.asyncio
async def test_https_unsupported_failure():
    response = _response(200, "http://example.com")
    response.extensions["netkatana.https.failed"] = True

    with pytest.raises(ValidationError) as exc_info:
        await https_unsupported(response)

    assert exc_info.value.message == "HTTPS is not supported"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_https_upgrade_redirect_missing_success():
    response = _response(200, "https://example.com/login", history=[_response(301, "http://example.com")])

    message = await https_upgrade_redirect_missing(response)

    assert message == "HTTP endpoint redirects to HTTPS"


@pytest.mark.asyncio
async def test_https_upgrade_redirect_missing_failure_when_final_response_is_http():
    response = _response(
        200,
        "http://example.com/login",
        history=[_response(301, "http://example.com")],
    )

    with pytest.raises(ValidationError) as exc_info:
        await https_upgrade_redirect_missing(response)

    assert exc_info.value.message == "HTTP endpoint does not redirect to HTTPS"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_https_upgrade_redirect_missing_success_when_location_targets_https():
    response = _response(301, "http://example.com", headers={"location": "https://www.example.com/login"})

    message = await https_upgrade_redirect_missing(response)

    assert message == "HTTP endpoint redirects to HTTPS"


@pytest.mark.asyncio
async def test_https_upgrade_redirect_missing_failure_when_location_is_missing():
    response = _response(301, "http://example.com")

    with pytest.raises(ValidationError) as exc_info:
        await https_upgrade_redirect_missing(response)

    assert exc_info.value.message == "HTTP endpoint does not redirect to HTTPS"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_https_upgrade_redirect_missing_failure_when_location_is_invalid():
    response = _response(301, "http://example.com", headers={"location": "http://[::1"})

    with pytest.raises(ValidationError) as exc_info:
        await https_upgrade_redirect_missing(response)

    assert exc_info.value.message == "HTTP endpoint does not redirect to HTTPS"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_https_upgrade_redirect_missing_not_applicable_for_https_origin():
    response = _response(200, "https://example.com")

    message = await https_upgrade_redirect_missing(response)

    assert message is None


@pytest.mark.asyncio
async def test_redirect_https_downgrade_no_redirects():
    response = _response(200, "https://example.com")

    message = await redirect_https_downgrade(response)

    assert message == "Redirect chain does not downgrade from HTTPS to HTTP"


@pytest.mark.asyncio
async def test_redirect_https_downgrade_with_downgrade():
    first = _response(301, "https://example.com")
    response = _response(200, "http://example.com/login", history=[first])

    with pytest.raises(ValidationError) as exc_info:
        await redirect_https_downgrade(response)

    assert exc_info.value.message == "Redirect chain downgrades from HTTPS to HTTP"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_redirect_https_downgrade_http_only_chain():
    first = _response(301, "http://example.com")
    response = _response(200, "http://example.com/login", history=[first])

    message = await redirect_https_downgrade(response)

    assert message is None


@pytest.mark.asyncio
async def test_redirect_chain_long_short():
    response = _response(
        200,
        "https://example.com/final",
        history=[
            _response(301, "https://example.com"),
            _response(302, "https://example.com/login"),
        ],
    )

    message = await redirect_chain_long(response)

    assert message == "Redirect chain is not long"


@pytest.mark.asyncio
async def test_redirect_chain_long_long():
    response = _response(
        200,
        "https://example.com/final",
        history=[
            _response(301, "https://example.com"),
            _response(302, "https://example.com/login"),
            _response(302, "https://example.com/app"),
        ],
    )

    with pytest.raises(ValidationError) as exc_info:
        await redirect_chain_long(response)

    assert exc_info.value.message == "Redirect chain is long"
    assert exc_info.value.metadata == {"redirects": "3"}


@pytest.mark.asyncio
async def test_redirect_chain_mixed_schemes_single_scheme():
    response = _response(
        200,
        "https://example.com/final",
        history=[_response(301, "https://example.com")],
    )

    message = await redirect_chain_mixed_schemes(response)

    assert message == "Redirect chain does not mix HTTP and HTTPS"


@pytest.mark.asyncio
async def test_redirect_chain_mixed_schemes_mixed():
    response = _response(
        200,
        "https://example.com/final",
        history=[
            _response(301, "http://example.com"),
            _response(302, "https://example.com/login"),
        ],
    )

    with pytest.raises(ValidationError) as exc_info:
        await redirect_chain_mixed_schemes(response)

    assert exc_info.value.message == "Redirect chain mixes HTTP and HTTPS"
    assert exc_info.value.metadata == {"schemes": "http, https"}
