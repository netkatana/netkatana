from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable, Generic, TypeVar

from httpx import Response
from pydantic import BaseModel

T = TypeVar("T")


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
    message: str
    detail: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class StrictTransportSecurityHeader:
    max_age: int
    include_subdomains: bool
    preload: bool


@dataclass(frozen=True)
class CrossOriginEmbedderPolicyHeader:
    policy: str
    report_to: str | None


@dataclass(frozen=True)
class CrossOriginOpenerPolicyHeader:
    policy: str
    report_to: str | None


@dataclass(frozen=True)
class SetCookieHeader:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    domain: str | None
    path: str | None


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


Validator = Callable[[T], Awaitable[str | None]]


@dataclass(kw_only=True)
class Rule(Generic[T]):
    code: str
    severity: Severity
    detail: str
    validator: Validator


HttpRule = Rule[Response]
TlsRule = Rule[TlsResult]
DnsRule = Rule[DnsResult]
