import re
from urllib.parse import urlparse

from netkatana.types import CrossOriginEmbedderPolicyHeader, StrictTransportSecurityHeader


def extract_host(target: str) -> str:
    """Extract the host (and port if present) from a URL or bare hostname."""
    if "://" not in target:
        target = f"https://{target}"
    return urlparse(target).netloc


_MAX_AGE_RE = re.compile(r"^max-age=(\d+)$", re.IGNORECASE)
_COEP_RE = re.compile(
    r'^(?P<policy>unsafe-none|require-corp|credentialless)(; report-to=(?P<report_to>"[^"]+"|[^";]+))?$'
)


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


def parse_cross_origin_embedder_policy_header(value: str) -> CrossOriginEmbedderPolicyHeader:
    m = _COEP_RE.fullmatch(value)
    if m is None:
        raise ValueError(f"Invalid Cross-Origin-Embedder-Policy header value: {value!r}")

    return CrossOriginEmbedderPolicyHeader(
        policy=m.group("policy"),
        report_to=m.group("report_to"),
    )


def parse_content_security_policy(value: str) -> dict[str, list[str]]:
    """Parse a CSP header value into a dict of lowercase directive name → list of lowercase source values."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        sources = [s.lower() for s in tokens[1:]]
        directives[name] = sources
    return directives
