import asyncio
import logging

import click
from rich.console import Console
from rich.logging import RichHandler

from netkatana.formatters import AbstractFormatter, JsonFormatter, JsonlFormatter, TableFormatter, VerboseFormatter
from netkatana.http import Client
from netkatana.rules import dns_rules, http_rules, tls_rules
from netkatana.scanners import DnsScanner, HttpScanner, TlsScanner
from netkatana.utils import extract_host

_formatters: dict[str, type[AbstractFormatter]] = {
    "verbose": VerboseFormatter,
    "jsonl": JsonlFormatter,
    "json": JsonFormatter,
    "table": TableFormatter,
}


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


@cli.command()
@click.argument("targets", nargs=-1, callback=_get_targets)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
@click.option("--show-passed", is_flag=True, default=False)
def http(targets: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    asyncio.run(_http(targets=targets, concurrency=concurrency, fmt=fmt, show_passed=show_passed))


async def _http(*, targets: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    async with Client() as client:
        scanner = HttpScanner(
            rules=http_rules,
            client=client,
            concurrency=concurrency,
        )

        with _formatters[fmt](show_passed=show_passed) as formatter:
            async for finding in scanner.scan(targets):
                formatter.emit(finding)


@cli.command()
@click.argument("targets", nargs=-1, callback=_get_targets)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
@click.option("--show-passed", is_flag=True, default=False)
def tls(targets: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    asyncio.run(_tls(targets=targets, concurrency=concurrency, fmt=fmt, show_passed=show_passed))


async def _tls(*, targets: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    scanner = TlsScanner(
        rules=tls_rules,
        concurrency=concurrency,
    )

    with _formatters[fmt](show_passed=show_passed) as formatter:
        async for finding in scanner.scan(targets):
            formatter.emit(finding)


@cli.command()
@click.argument("targets", nargs=-1, callback=_get_targets)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
@click.option("--show-passed", is_flag=True, default=False)
def dns(targets: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    asyncio.run(_dns(targets=targets, concurrency=concurrency, fmt=fmt, show_passed=show_passed))


async def _dns(*, targets: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    scanner = DnsScanner(
        rules=dns_rules,
        concurrency=concurrency,
    )

    with _formatters[fmt](show_passed=show_passed) as formatter:
        async for finding in scanner.scan(targets):
            formatter.emit(finding)
