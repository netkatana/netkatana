import httpx
import pytest
import respx

from netkatana.http import Client, OutOfBoundsRedirect, RedirectLoop, TooManyRedirects


class TestClient:
    @respx.mock
    @pytest.mark.asyncio
    async def test_get_returns_response(self):
        respx.get("https://example.com/").mock(return_value=httpx.Response(200))

        async with Client() as client:
            response = await client.get("https://example.com/")

        assert response.status_code == 200
        assert response.history == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_follows_single_redirect(self):
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(301, headers={"location": "https://example.com/final"})
        )
        respx.get("https://example.com/final").mock(return_value=httpx.Response(200))

        async with Client() as client:
            response = await client.get("https://example.com/")

        assert response.status_code == 200
        assert len(response.history) == 1
        assert response.history[0].status_code == 301

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_raises_too_many_redirects(self):
        for i in range(5):
            respx.get(f"https://example.com/?n={i}").mock(
                return_value=httpx.Response(301, headers={"location": f"https://example.com/?n={i + 1}"})
            )

        async with Client(max_redirects=3) as client:
            with pytest.raises(TooManyRedirects) as exc_info:
                await client.get("https://example.com/?n=0")

        assert exc_info.value.response.status_code == 301

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_raises_redirect_loop(self):
        respx.get("https://example.com/a").mock(
            return_value=httpx.Response(301, headers={"location": "https://example.com/b"})
        )
        respx.get("https://example.com/b").mock(
            return_value=httpx.Response(301, headers={"location": "https://example.com/a"})
        )

        async with Client() as client:
            with pytest.raises(RedirectLoop) as exc_info:
                await client.get("https://example.com/a")

        assert exc_info.value.response.status_code == 301

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_raises_out_of_bounds_redirect(self):
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(301, headers={"location": "https://other.com/"})
        )

        async with Client() as client:
            with pytest.raises(OutOfBoundsRedirect) as exc_info:
                await client.get("https://example.com/")

        assert exc_info.value.response.status_code == 301
