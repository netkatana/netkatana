import httpx
import pytest

from netkatana.http import Client, OutOfBoundsRedirect, RedirectLoop, TooManyRedirects


class TestClientGet:
    @pytest.mark.asyncio
    async def test_returns_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)

        async with Client(transport=httpx.MockTransport(handler)) as client:
            response = await client.get("https://example.com/")

        assert response.status_code == 200
        assert response.history == []

    @pytest.mark.asyncio
    async def test_follows_single_redirect(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(301, headers={"location": "https://example.com/final"})
            return httpx.Response(200)

        async with Client(transport=httpx.MockTransport(handler)) as client:
            response = await client.get("https://example.com/")

        assert response.status_code == 200
        assert len(response.history) == 1
        assert response.history[0].status_code == 301

    @pytest.mark.asyncio
    async def test_raises_too_many_redirects(self):
        def handler(request: httpx.Request) -> httpx.Response:
            n = int(request.url.params.get("n", "0"))
            return httpx.Response(301, headers={"location": f"https://example.com/?n={n + 1}"})

        async with Client(max_redirects=3, transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(TooManyRedirects) as exc_info:
                await client.get("https://example.com/?n=0")

        assert exc_info.value.response.status_code == 301

    @pytest.mark.asyncio
    async def test_raises_redirect_loop(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/a":
                return httpx.Response(301, headers={"location": "https://example.com/b"})
            return httpx.Response(301, headers={"location": "https://example.com/a"})

        async with Client(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(RedirectLoop) as exc_info:
                await client.get("https://example.com/a")

        assert exc_info.value.response.status_code == 301

    @pytest.mark.asyncio
    async def test_raises_out_of_bounds_redirect(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(301, headers={"location": "https://other.com/"})

        async with Client(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(OutOfBoundsRedirect) as exc_info:
                await client.get("https://example.com/")

        assert exc_info.value.response.status_code == 301
