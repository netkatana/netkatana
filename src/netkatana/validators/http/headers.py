from httpx import Response

from netkatana.exceptions import ValidationError


async def strict_transport_security_missing(response: Response) -> str | None:
    if "strict-transport-security" not in response.headers:
        raise ValidationError("Strict-Transport-Security (HSTS) missing")

    return "Strict-Transport-Security (HSTS) present"
