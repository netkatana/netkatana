import re
from urllib.parse import urlparse

from netkatana.models import StrictTransportSecurityHeader


def extract_host(target: str) -> str:
    """Extract the host (and port if present) from a URL or bare hostname."""
    if "://" not in target:
        target = f"https://{target}"
    return urlparse(target).netloc


_MAX_AGE_RE = re.compile(r"^max-age=(\d+)$", re.IGNORECASE)


def parse_strict_transport_security_header(value: str) -> StrictTransportSecurityHeader:
    max_age = None
    include_subdomains = False
    preload = False

    for directive in (d.strip() for d in value.split(";")):
        if not directive:
            continue
        m = _MAX_AGE_RE.match(directive)
        if m:
            max_age = int(m.group(1))
        elif directive.lower() == "includesubdomains":
            include_subdomains = True
        elif directive.lower() == "preload":
            preload = True

    if max_age is None:
        raise ValueError(f"Invalid Strict-Transport-Security header value: {value!r}")

    return StrictTransportSecurityHeader(
        max_age=max_age,
        include_subdomains=include_subdomains,
        preload=preload,
    )
