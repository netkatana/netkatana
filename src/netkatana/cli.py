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


def _get_hosts(ctx: click.Context, param: click.Parameter, hosts: tuple[str, ...]) -> list[str]:
    targets = list(hosts)

    stdin = click.get_text_stream("stdin")
    if not stdin.isatty():
        targets.extend(line.strip() for line in stdin if line.strip())

    if not targets:
        raise click.UsageError("Provide hosts as arguments or via stdin.")

    return [extract_host(h) for h in targets]


@cli.command()
@click.argument("hosts", nargs=-1, callback=_get_hosts)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
@click.option("--show-passed", is_flag=True, default=False)
def http(hosts: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    asyncio.run(_http(hosts=hosts, concurrency=concurrency, fmt=fmt, show_passed=show_passed))


async def _http(*, hosts: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    async with Client() as client:
        scanner = HttpScanner(
            rules=http_rules,
            client=client,
            concurrency=concurrency,
        )

        with _formatters[fmt](show_passed=show_passed) as formatter:
            async for finding in scanner.check_hosts(hosts):
                formatter.emit(finding)


@cli.command()
@click.argument("hosts", nargs=-1, callback=_get_hosts)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
@click.option("--show-passed", is_flag=True, default=False)
def tls(hosts: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    asyncio.run(_tls(hosts=hosts, concurrency=concurrency, fmt=fmt, show_passed=show_passed))


async def _tls(*, hosts: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    scanner = TlsScanner(
        rules=tls_rules,
        concurrency=concurrency,
    )

    with _formatters[fmt](show_passed=show_passed) as formatter:
        async for finding in scanner.run(hosts):
            formatter.emit(finding)


@cli.command()
@click.argument("domains", nargs=-1, callback=_get_hosts)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
@click.option("--show-passed", is_flag=True, default=False)
def dns(domains: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    asyncio.run(_dns(domains=domains, concurrency=concurrency, fmt=fmt, show_passed=show_passed))


async def _dns(*, domains: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    scanner = DnsScanner(
        rules=dns_rules,
        concurrency=concurrency,
    )

    with _formatters[fmt](show_passed=show_passed) as formatter:
        async for finding in scanner.run(domains):
            formatter.emit(finding)
