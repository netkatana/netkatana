import json
from abc import ABC, abstractmethod
from typing import Any, Self

from rich.console import Console
from rich.table import Table
from rich.text import Text

from netkatana.types import Finding, Severity

_SEVERITY_SYMBOL: dict[Severity, tuple[str, str]] = {
    Severity.PASS: ("P", "bold green"),
    Severity.NOTICE: ("N", "bold cyan"),
    Severity.WARNING: ("W", "bold yellow"),
    Severity.CRITICAL: ("C", "bold red"),
}

_INDENT = "    "


class Formatter(ABC):
    @abstractmethod
    def emit(self, finding: Finding, severities: set[Severity]) -> None: ...

    def flush(self) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: Any) -> None:
        self.flush()


class VerboseFormatter(Formatter):
    def __init__(self) -> None:
        self._console = Console(highlight=False)

    def emit(self, finding: Finding, severities: set[Severity]) -> None:
        if finding.severity not in severities:
            return

        symbol, style = _SEVERITY_SYMBOL[finding.severity]

        header = Text()
        header.append(f"[{symbol}]", style=style)
        header.append(" ")
        header.append(finding.host, style="white")
        header.append(" - ")
        header.append(finding.message)
        header.append(f" [{finding.code}]", style="dim")
        self._console.print(header)

        self._console.print(f"{_INDENT}{finding.detail}")
        self._console.print()


def _serialize(finding: Finding) -> dict[str, object]:
    return {
        "host": finding.host,
        "code": finding.code,
        "severity": finding.severity.value,
        "message": finding.message,
        "detail": finding.detail,
        "metadata": finding.metadata,
    }


class JsonlFormatter(Formatter):
    def emit(self, finding: Finding, severities: set[Severity]) -> None:
        if finding.severity not in severities:
            return
        print(json.dumps(_serialize(finding)))


class JsonFormatter(Formatter):
    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def emit(self, finding: Finding, severities: set[Severity]) -> None:
        if finding.severity not in severities:
            return
        self._findings.append(finding)

    def flush(self) -> None:
        print(json.dumps([_serialize(finding) for finding in self._findings], indent=2))


class TableFormatter(Formatter):
    def __init__(self) -> None:
        self._console = Console(highlight=False)
        self._findings: list[Finding] = []

    def emit(self, finding: Finding, severities: set[Severity]) -> None:
        if finding.severity not in severities:
            return
        self._findings.append(finding)

    def flush(self) -> None:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Host", style="white")
        table.add_column("Finding")
        table.add_column("Code", style="dim")

        for finding in self._findings:
            symbol, style = _SEVERITY_SYMBOL[finding.severity]
            table.add_row(
                Text(finding.severity, style=style),
                finding.host,
                finding.message,
                finding.code,
            )

        self._console.print(table)
