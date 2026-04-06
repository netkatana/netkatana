from contextlib import AsyncExitStack

from httpx import AsyncBaseTransport, AsyncClient, Response


class RedirectError(Exception):
    def __init__(self, message: str, *, response: Response) -> None:
        super().__init__(message)
        self.response = response


class TooManyRedirects(RedirectError): ...


class RedirectLoop(RedirectError): ...


class OutOfBoundsRedirect(RedirectError): ...


class Client:
    def __init__(
        self,
        max_redirects: int = 10,
        verify: bool = False,
        transport: AsyncBaseTransport | None = None,
    ) -> None:
        self._max_redirects = max_redirects
        self._verify = verify
        self._transport = transport
        self._exit_stack = AsyncExitStack()
        self._client: AsyncClient

    async def __aenter__(self) -> "Client":
        self._client = await self._exit_stack.enter_async_context(
            AsyncClient(verify=self._verify, follow_redirects=False, transport=self._transport)
        )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._exit_stack.__aexit__(*exc_info)

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
            next_url = str(next_request.url)

            if next_url in visited:
                raise RedirectLoop("Redirect loop detected.", response=response)

            if len(history) >= self._max_redirects:
                raise TooManyRedirects("Exceeded maximum allowed redirects.", response=response)

            if next_request.url.host != origin_host:
                raise OutOfBoundsRedirect("Redirect out of bounds.", response=response)

            visited.add(str(request.url))
            history.append(response)
            request = next_request
