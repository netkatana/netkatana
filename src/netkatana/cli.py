import asyncio
import logging

import click
from rich.console import Console
from rich.logging import RichHandler

from netkatana.formatters import Formatter, JsonFormatter, JsonlFormatter, TableFormatter, VerboseFormatter
from netkatana.http import Client
from netkatana.rules import dns_rules, http_rules, tls_rules
from netkatana.scanners import DnsScanner, HttpScanner, TlsScanner
from netkatana.types import Severity
from netkatana.utils import extract_host

_formatters: dict[str, type[Formatter]] = {
    "verbose": VerboseFormatter,
    "jsonl": JsonlFormatter,
    "json": JsonFormatter,
    "table": TableFormatter,
}

_DEFAULT_CONCURRENCY = 100
_FORMAT_CHOICES = click.Choice(_formatters.keys())
_SEVERITY_CHOICES = click.Choice([severity.value for severity in Severity])


@click.group()
def cli() -> None:
    logging.basicConfig(handlers=[RichHandler(console=Console(stderr=True))], format="%(message)s")


def _get_targets(ctx: click.Context, param: click.Parameter, values: tuple[str, ...]) -> list[str]:
    targets = list(values)

    stdin = click.get_text_stream("stdin")
    if not stdin.isatty():
        targets.extend(line.strip() for line in stdin if line.strip())

    if not targets:
        raise click.UsageError("Provide hosts as arguments or via stdin.")

    return [extract_host(h) for h in targets]


def _get_severities(values: tuple[str, ...]) -> set[Severity]:
    if not values:
        return {Severity.CRITICAL, Severity.WARNING, Severity.NOTICE}

    return {Severity(value) for value in values}


@cli.command()
@click.argument("targets", nargs=-1, callback=_get_targets)
@click.option("-c", "--concurrency", default=_DEFAULT_CONCURRENCY, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=_FORMAT_CHOICES)
@click.option("-s", "--severity", "severity_values", multiple=True, type=_SEVERITY_CHOICES)
def http(targets: list[str], concurrency: int, fmt: str, severity_values: tuple[str, ...]) -> None:
    asyncio.run(
        _http(
            targets=targets,
            concurrency=concurrency,
            fmt=fmt,
            severities=_get_severities(severity_values),
        )
    )


async def _http(*, targets: list[str], concurrency: int, fmt: str, severities: set[Severity]) -> None:
    async with Client() as client:
        scanner = HttpScanner(
            rules=http_rules,
            client=client,
            concurrency=concurrency,
        )

        with _formatters[fmt]() as formatter:
            async for finding in scanner.scan(targets):
                formatter.emit(finding, severities)


@cli.command()
@click.argument("targets", nargs=-1, callback=_get_targets)
@click.option("-c", "--concurrency", default=_DEFAULT_CONCURRENCY, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=_FORMAT_CHOICES)
@click.option("-s", "--severity", "severity_values", multiple=True, type=_SEVERITY_CHOICES)
def tls(targets: list[str], concurrency: int, fmt: str, severity_values: tuple[str, ...]) -> None:
    asyncio.run(
        _tls(
            targets=targets,
            concurrency=concurrency,
            fmt=fmt,
            severities=_get_severities(severity_values),
        )
    )


async def _tls(*, targets: list[str], concurrency: int, fmt: str, severities: set[Severity]) -> None:
    scanner = TlsScanner(
        rules=tls_rules,
        concurrency=concurrency,
    )

    with _formatters[fmt]() as formatter:
        async for finding in scanner.scan(targets):
            formatter.emit(finding, severities)


@cli.command()
@click.argument("targets", nargs=-1, callback=_get_targets)
@click.option("-c", "--concurrency", default=_DEFAULT_CONCURRENCY, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=_FORMAT_CHOICES)
@click.option("-s", "--severity", "severity_values", multiple=True, type=_SEVERITY_CHOICES)
def dns(targets: list[str], concurrency: int, fmt: str, severity_values: tuple[str, ...]) -> None:
    asyncio.run(
        _dns(
            targets=targets,
            concurrency=concurrency,
            fmt=fmt,
            severities=_get_severities(severity_values),
        )
    )


async def _dns(*, targets: list[str], concurrency: int, fmt: str, severities: set[Severity]) -> None:
    scanner = DnsScanner(
        rules=dns_rules,
        concurrency=concurrency,
    )

    with _formatters[fmt]() as formatter:
        async for finding in scanner.scan(targets):
            formatter.emit(finding, severities)
