from typing import Any, Self

from httpx import AsyncClient, Response


class RedirectError(Exception):
    def __init__(self, message: str, *, response: Response) -> None:
        super().__init__(message)
        self.response = response


class TooManyRedirects(RedirectError): ...


class RedirectLoop(RedirectError): ...


class OutOfBoundsRedirect(RedirectError): ...


class Client:
    def __init__(self, *, max_redirects: int = 10, verify: bool = False) -> None:
        self._max_redirects = max_redirects
        self._client = AsyncClient(verify=verify, follow_redirects=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        await self.aclose()

    async def get(self, url: str) -> Response:
        request = self._client.build_request("GET", url)
        origin_host = request.url.host
        history: list[Response] = []
        visited: set[str] = set()

        while True:
            response = await self._client.send(request, follow_redirects=False)
            response.history = history[:]

            if not response.has_redirect_location:
                return response

            next_request = response.next_request
            assert next_request is not None
            next_url = str(next_request.url)

            if next_url in visited:
                raise RedirectLoop("Redirect loop detected.", response=response)

            if len(history) >= self._max_redirects:
                raise TooManyRedirects("Exceeded maximum allowed redirects.", response=response)

            if next_request.url.host != origin_host:
                raise OutOfBoundsRedirect(
                    f"Redirect out of bounds. From {origin_host!r} to {next_request.url.host!r}.", response=response
                )

            visited.add(str(request.url))
            history.append(response)
            request = next_request
