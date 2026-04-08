import json
from abc import ABC, abstractmethod
from typing import Any, Self

from rich.console import Console
from rich.table import Table
from rich.text import Text

from netkatana.types import Finding, Severity

_SEVERITY_SYMBOL: dict[Severity, tuple[str, str]] = {
    Severity.PASS: ("P", "bold green"),
    Severity.NOTICE: ("I", "bold cyan"),
    Severity.WARNING: ("W", "bold yellow"),
    Severity.CRITICAL: ("C", "bold red"),
}

_INDENT = "    "


class AbstractFormatter(ABC):
    def __init__(self, show_passed: bool = False) -> None:
        self._show_passed = show_passed

    @abstractmethod
    def emit(self, finding: Finding) -> None: ...

    def flush(self) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: Any) -> None:
        self.flush()


class VerboseFormatter(AbstractFormatter):
    def __init__(self, show_passed: bool = False) -> None:
        super().__init__(show_passed)
        self._console = Console(highlight=False)

    def emit(self, finding: Finding) -> None:
        if finding.severity == Severity.PASS and not self._show_passed:
            return

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
        self._console.print()


def _serialize(finding: Finding) -> dict[str, object]:
    return {
        "host": finding.host,
        "code": finding.code,
        "severity": finding.severity.value,
        "title": finding.title,
        "detail": finding.detail,
        "metadata": finding.metadata,
    }


class JsonlFormatter(AbstractFormatter):
    def __init__(self, show_passed: bool = False) -> None:
        super().__init__(show_passed)

    def emit(self, finding: Finding) -> None:
        if finding.severity == Severity.PASS and not self._show_passed:
            return
        print(json.dumps(_serialize(finding)))


class JsonFormatter(AbstractFormatter):
    def __init__(self, show_passed: bool = False) -> None:
        super().__init__(show_passed)
        self._findings: list[Finding] = []

    def emit(self, finding: Finding) -> None:
        if finding.severity == Severity.PASS and not self._show_passed:
            return
        self._findings.append(finding)

    def flush(self) -> None:
        print(json.dumps([_serialize(finding) for finding in self._findings], indent=2))


class TableFormatter(AbstractFormatter):
    def __init__(self, show_passed: bool = False) -> None:
        super().__init__(show_passed)
        self._console = Console(highlight=False)
        self._findings: list[Finding] = []

    def emit(self, finding: Finding) -> None:
        if finding.severity == Severity.PASS and not self._show_passed:
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
                finding.title,
                finding.code,
            )

        self._console.print(table)
