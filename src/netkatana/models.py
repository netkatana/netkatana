from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from httpx import Response
from pydantic import BaseModel


class Severity(str, Enum):
    PASS = "pass"
    NOTICE = "notice"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Finding:
    code: str
    severity: Severity
    title: str
    detail: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class HostFinding:
    host: str
    finding: Finding


class AbstractHttpCheck(ABC):
    @abstractmethod
    async def check(self, response: Response) -> list[Finding]:
        pass


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


class AbstractTlsCheck(ABC):
    @abstractmethod
    async def check(self, result: TlsResult) -> list[Finding]:
        pass
