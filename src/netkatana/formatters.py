import json
from abc import ABC, abstractmethod
from typing import Self

from rich.console import Console
from rich.table import Table
from rich.text import Text

from netkatana.models import Finding, Severity

_SEVERITY_SYMBOL: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("C", "bold red"),
    Severity.WARNING: ("W", "bold yellow"),
    Severity.NOTICE: ("I", "bold cyan"),
}

_INDENT = "    "


class AbstractFormatter(ABC):
    @abstractmethod
    def emit(self, finding: Finding) -> None: ...

    def flush(self) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.flush()


class VerboseFormatter(AbstractFormatter):
    def __init__(self) -> None:
        self._console = Console(highlight=False)

    def emit(self, finding: Finding) -> None:
        symbol, style = _SEVERITY_SYMBOL[finding.severity]

        header = Text()
        header.append(f"[{symbol}]", style=style)
        header.append(" ")
        header.append(finding.host, style="white")
        header.append(" - ")
        header.append(finding.title)
        header.append(f" [{finding.code}]", style="dim")
        self._console.print(header)

        self._console.print(f"{_INDENT}{finding.detail}")

        for ref in finding.references:
            line = Text()
            line.append(_INDENT)
            line.append("ref", style="dim")
            line.append(" ")
            line.append(ref, style="link")
            self._console.print(line)

        self._console.print()


def _serialize(finding: Finding) -> dict[str, object]:
    return {
        "code": finding.code,
        "severity": finding.severity.value,
        "title": finding.title,
        "detail": finding.detail,
        "host": finding.host,
        "references": finding.references,
    }


class JsonlFormatter(AbstractFormatter):
    def emit(self, finding: Finding) -> None:
        print(json.dumps(_serialize(finding)))


class JsonFormatter(AbstractFormatter):
    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def emit(self, finding: Finding) -> None:
        self._findings.append(finding)

    def flush(self) -> None:
        print(json.dumps([_serialize(f) for f in self._findings], indent=2))


class TableFormatter(AbstractFormatter):
    def __init__(self) -> None:
        self._console = Console(highlight=False)
        self._findings: list[Finding] = []

    def emit(self, finding: Finding) -> None:
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
                finding.title,
                finding.code,
            )

        self._console.print(table)
