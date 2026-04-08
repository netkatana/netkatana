from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable

from httpx import Response
from pydantic import BaseModel


class Severity(str, Enum):
    PASS = "pass"
    NOTICE = "notice"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Finding:
    host: str
    code: str
    severity: Severity
    title: str
    detail: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class StrictTransportSecurityHeader:
    max_age: int
    include_subdomains: bool
    preload: bool


class TlsResult(BaseModel):
    host: str
    port: str
    ip: str
    tls_version: str
    cipher: str
    expired: bool = False
    self_signed: bool = False
    mismatched: bool = False
    revoked: bool = False
    untrusted: bool = False


class DnsResult(BaseModel):
    domain: str
    txt: list[str]
    dmarc_txt: list[str]


@dataclass(kw_only=True)
class HttpRule:
    code: str
    severity: Severity
    detail: str
    validator: Callable[[Response], Awaitable[str | None]]


@dataclass(kw_only=True)
class TlsRule:
    code: str
    severity: Severity
    detail: str
    validator: Callable[[TlsResult], Awaitable[str | None]]


@dataclass(kw_only=True)
class DnsRule:
    code: str
    severity: Severity
    detail: str
    validator: Callable[[DnsResult], Awaitable[str | None]]
