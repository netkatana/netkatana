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

# https://datatracker.ietf.org/doc/html/rfc6265#section-4.1.1
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_VALUE_RE = re.compile(r'^(?:[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*|"[\x20-\x21\x23-\x7E]*")$')


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
    parts = _split_set_cookie_parts(value)
    cookie_name, _cookie_value = _parse_set_cookie_name_value_pair(parts[0])
    secure, http_only, same_site, domain, path = _parse_set_cookie_attributes(parts[1:])

    return SetCookieHeader(
        name=cookie_name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        domain=domain,
        path=path,
    )


def _split_set_cookie_parts(value: str) -> list[str]:
    parts = [part.strip() for part in value.split(";")]
    if not parts or not parts[0]:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    return parts


def _parse_set_cookie_name_value_pair(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    cookie_name, cookie_value = value.split("=", 1)
    cookie_name = cookie_name.strip()

    if not cookie_name:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    if _COOKIE_NAME_RE.match(cookie_name) is None:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    cookie_value = cookie_value.strip()
    if _COOKIE_VALUE_RE.match(cookie_value) is None:
        raise ValueError(f"Invalid Set-Cookie header value: {value!r}")

    return cookie_name, cookie_value


def _parse_set_cookie_attributes(attributes: list[str]) -> tuple[bool, bool, str | None, str | None, str | None]:
    secure = False
    http_only = False
    same_site = None
    domain = None
    path = None

    for attribute in attributes:
        if not attribute:
            continue

        attribute_name, separator, attribute_value = attribute.partition("=")
        attribute_name = attribute_name.strip().lower()

        if separator:
            attribute_value = attribute_value.strip()

        if attribute_name == "secure" and not separator:
            secure = True
        elif attribute_name == "httponly" and not separator:
            http_only = True
        elif attribute_name == "samesite" and separator:
            same_site = attribute_value
        elif attribute_name == "domain" and separator:
            domain = attribute_value
        elif attribute_name == "path" and separator:
            path = attribute_value

    return secure, http_only, same_site, domain, path
