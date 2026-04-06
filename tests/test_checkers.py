import logging
from unittest.mock import AsyncMock

import httpx
import pytest

from netkatana.checkers import HttpChecker
from netkatana.http import Client, TooManyRedirects


class TestHttpChecker:
    @pytest.mark.asyncio
    async def test_check_host_prepends_https(self):
        client = AsyncMock(spec=Client)
        client.get.return_value = httpx.Response(200)

        checker = HttpChecker(checks=[], client=client)
        await checker.check_host("example.com")

        client.get.assert_called_once_with("https://example.com")

    @pytest.mark.asyncio
    async def test_check_host_unreachable_returns_empty(self, caplog):
        client = AsyncMock(spec=Client)
        client.get.side_effect = httpx.ConnectError("Connection refused")

        checker = HttpChecker(checks=[], client=client)

        with caplog.at_level(logging.WARNING):
            result = await checker.check_host("unreachable.example.com")

        assert result == []
        assert "unreachable.example.com" in caplog.text

    @pytest.mark.asyncio
    async def test_check_host_redirect_error_uses_last_response(self, caplog):
        last_response = httpx.Response(301, headers={"location": "https://other.com/"})
        client = AsyncMock(spec=Client)
        client.get.side_effect = TooManyRedirects("Exceeded maximum allowed redirects.", response=last_response)

        checker = HttpChecker(checks=[], client=client)

        with caplog.at_level(logging.WARNING):
            result = await checker.check_host("example.com")

        assert result == []
        assert "example.com" in caplog.text
