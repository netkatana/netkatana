import pytest
from httpx import Request, Response

from netkatana.exceptions import ValidationError
from netkatana.validators.http.response import (
    redirect_chain_long,
    redirect_chain_mixed_schemes,
    redirect_https_downgrade,
    status_server_error,
)


def _response(status_code: int, url: str, history: list[Response] | None = None) -> Response:
    response = Response(status_code, request=Request("GET", url))
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
