from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from httpx import Response


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    NOTICE = "notice"


@dataclass
class Finding:
    code: str
    severity: Severity
    title: str
    detail: str
    host: str = ""
    references: list[str] = field(default_factory=list)


class AbstractCheck(ABC):
    @abstractmethod
    async def check(self, response: Response) -> list[Finding]:
        pass
