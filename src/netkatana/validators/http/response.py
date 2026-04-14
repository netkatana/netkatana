from httpx import Response

from netkatana.exceptions import ValidationError

_LONG_REDIRECT_CHAIN = 2


async def status_server_error(response: Response) -> str | None:
    if 500 <= response.status_code <= 599:
        raise ValidationError(
            "Response returned a server error status", metadata={"status_code": str(response.status_code)}
        )

    return "Response did not return a server error status"


async def https_unsupported(response: Response) -> str | None:
    if response.extensions.get("netkatana.https.failed", False):
        raise ValidationError("HTTPS is not supported")

    return "HTTPS is supported"


async def https_upgrade_redirect_missing(response: Response) -> str | None:
    schemes = _redirect_schemes(response)

    if not schemes or schemes[0] != "http":
        return None

    if "https" not in schemes[1:]:
        raise ValidationError("HTTP endpoint does not redirect to HTTPS")

    https_seen = False
    for scheme in schemes[1:]:
        if scheme == "https":
            https_seen = True
            continue

        if https_seen and scheme == "http":
            raise ValidationError("HTTP endpoint does not redirect to HTTPS")

    return "HTTP endpoint redirects to HTTPS"


def _redirect_chain(response: Response) -> list[Response]:
    return [*response.history, response]


def _redirect_schemes(response: Response) -> list[str]:
    return [hop.request.url.scheme for hop in _redirect_chain(response)]


async def redirect_https_downgrade(response: Response) -> str | None:
    schemes = _redirect_schemes(response)

    if "https" not in schemes:
        return None

    for previous, current in zip(schemes, schemes[1:], strict=False):
        if previous == "https" and current == "http":
            raise ValidationError("Redirect chain downgrades from HTTPS to HTTP")

    return "Redirect chain does not downgrade from HTTPS to HTTP"


async def redirect_chain_long(response: Response) -> str | None:
    chain_length = len(response.history)

    if chain_length > _LONG_REDIRECT_CHAIN:
        raise ValidationError("Redirect chain is long", metadata={"redirects": str(chain_length)})

    return "Redirect chain is not long"


async def redirect_chain_mixed_schemes(response: Response) -> str | None:
    schemes = set(_redirect_schemes(response))

    if len(schemes) > 1:
        raise ValidationError(
            "Redirect chain mixes HTTP and HTTPS",
            metadata={"schemes": ", ".join(sorted(schemes))},
        )

    return "Redirect chain does not mix HTTP and HTTPS"
