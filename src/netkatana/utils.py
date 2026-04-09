import re
from urllib.parse import urlparse

from netkatana.types import (
    CrossOriginEmbedderPolicyHeader,
    CrossOriginOpenerPolicyHeader,
    SetCookieHeader,
    StrictTransportSecurityHeader,
)


def extract_host(target: str) -> str:
    """Extract the host (and port if present) from a URL or bare hostname."""
    if "://" not in target:
        target = f"https://{target}"
    return urlparse(target).netloc


_MAX_AGE_RE = re.compile(r"^max-age=(\d+)$", re.IGNORECASE)
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_VALUE_RE = re.compile(r'^(?:[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*|"(?:[\x20-\x21\x23-\x7E]*)")$')
_COEP_RE = re.compile(
    r'^(?P<policy>unsafe-none|require-corp|credentialless)(; report-to=(?P<report_to>"[^"]+"|[^";]+))?$'
)
_COOP_RE = re.compile(
    r"^(?P<policy>unsafe-none|same-origin-allow-popups|same-origin|noopener-allow-popups)"
    r'(; report-to=(?P<report_to>"[^"]+"|[^";]+))?$'
)
_REFERRER_POLICY_VALUES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "origin",
    "strict-origin",
    "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


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
    match = _COEP_RE.match(value)

    if match is None:
        raise ValueError(f"Invalid Cross-Origin-Embedder-Policy header value: {value!r}")

    return CrossOriginEmbedderPolicyHeader(
        policy=match.group("policy"),
        report_to=match.group("report_to"),
    )


def parse_cross_origin_opener_policy_header(value: str) -> CrossOriginOpenerPolicyHeader:
    match = _COOP_RE.match(value)

    if match is None:
        raise ValueError(f"Invalid Cross-Origin-Opener-Policy header value: {value!r}")

    return CrossOriginOpenerPolicyHeader(
        policy=match.group("policy"),
        report_to=match.group("report_to"),
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


def parse_referrer_policy_header(value: str) -> str:
    policy = value.strip().lower()

    if policy not in _REFERRER_POLICY_VALUES:
        raise ValueError(f"Invalid Referrer-Policy header value: {value!r}")

    return policy


def parse_x_frame_options_header(value: str) -> str:
    option = value.strip().lower()

    if option not in {"deny", "sameorigin"}:
        raise ValueError(f"Invalid X-Frame-Options header value: {value!r}")

    return option


def parse_set_cookie_header(value: str) -> SetCookieHeader:
    parts = [part.strip() for part in value.split(";")]
    if not parts or not parts[0]:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    cookie_pair = parts[0]
    if "=" not in cookie_pair:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    name, _cookie_value = cookie_pair.split("=", 1)
    name = name.strip()
    if not name:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")
    if _COOKIE_NAME_RE.match(name) is None:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    cookie_value = _cookie_value.strip()
    if _COOKIE_VALUE_RE.match(cookie_value) is None:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    secure = False
    http_only = False
    same_site = None
    domain = None
    path = None

    for attribute in parts[1:]:
        if not attribute:
            continue

        key, separator, attribute_value = attribute.partition("=")
        key = key.strip().lower()

        if separator:
            attribute_value = attribute_value.strip()

        if key == "secure" and not separator:
            secure = True
        elif key == "httponly" and not separator:
            http_only = True
        elif key == "samesite" and separator:
            same_site = attribute_value
        elif key == "domain" and separator:
            domain = attribute_value
        elif key == "path" and separator:
            path = attribute_value

    return SetCookieHeader(
        name=name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        domain=domain,
        path=path,
    )
