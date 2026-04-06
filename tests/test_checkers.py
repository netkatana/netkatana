import logging
from unittest.mock import AsyncMock

import httpx
import pytest

from netkatana.checkers import HttpChecker


class TestHttpChecker:
    @pytest.mark.asyncio
    async def test_check_host_prepends_https(self):
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = httpx.Response(200)

        checker = HttpChecker(checks=[], client=client)
        await checker.check_host("example.com")

        client.get.assert_called_once_with("https://example.com")

    @pytest.mark.asyncio
    async def test_check_host_unreachable_returns_empty(self, caplog):
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.side_effect = httpx.ConnectError("Connection refused")

        checker = HttpChecker(checks=[], client=client)

        with caplog.at_level(logging.WARNING):
            result = await checker.check_host("unreachable.example.com")

        assert result == []
        assert "unreachable.example.com" in caplog.text
