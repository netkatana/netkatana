import re
from urllib.parse import urlparse

from netkatana.models import StrictTransportSecurityHeader


def extract_host(target: str) -> str:
    """Extract the host (and port if present) from a URL or bare hostname."""
    if "://" not in target:
        target = f"https://{target}"
    return urlparse(target).netloc


def parse_strict_transport_security_header(value: str) -> StrictTransportSecurityHeader:
    m = _hsts_regex.match(value)
    if not m:
        raise ValueError(f"Invalid Strict-Transport-Security header value: {value!r}")
    return StrictTransportSecurityHeader(
        max_age=int(m.group("max_age")),
        include_subdomains=m.group("include_subdomains") is not None,
        preload=m.group("preload") is not None,
    )


_hsts_regex = re.compile(
    r"^max-age=(?P<max_age>\d+)"
    r"(?:; (?P<include_subdomains>includeSubDomains))?"
    r"(?:; (?P<preload>preload))?$",
    re.IGNORECASE,
)
