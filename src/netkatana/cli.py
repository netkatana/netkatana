import asyncio
import logging

import click
from httpx import AsyncClient
from rich.logging import RichHandler

from netkatana.checkers import HttpChecker, TlsChecker
from netkatana.checks.http.headers import ContentSecurityPolicyMissing, StrictTransportSecurityMissing
from netkatana.checks.tls import (
    TlsCertExpired,
    TlsCertMismatched,
    TlsCertRevoked,
    TlsCertSelfSigned,
    TlsCertUntrusted,
    TlsCipherWeak,
    TlsVersionDeprecated,
    TlsVersionOutdated,
)
from netkatana.formatters import AbstractFormatter, JsonFormatter, JsonlFormatter, TableFormatter, VerboseFormatter

_formatters: dict[str, type[AbstractFormatter]] = {
    "verbose": VerboseFormatter,
    "jsonl": JsonlFormatter,
    "json": JsonFormatter,
    "table": TableFormatter,
}


@click.group()
def cli() -> None:
    logging.basicConfig(handlers=[RichHandler()], format="%(message)s")


@cli.command()
@click.argument("hosts", nargs=-1)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
def http(hosts: tuple[str, ...], concurrency: int, fmt: str) -> None:
    asyncio.run(_http(hosts=hosts, concurrency=concurrency, fmt=fmt))


async def _http(*, hosts: tuple[str, ...], concurrency: int, fmt: str) -> None:
    async with AsyncClient(verify=False, follow_redirects=True) as client:
        checker = HttpChecker(
            checks=[StrictTransportSecurityMissing(), ContentSecurityPolicyMissing()],
            client=client,
            concurrency=concurrency,
        )

        with _formatters[fmt]() as formatter:
            async for host_finding in checker.run(hosts):
                formatter.emit(host_finding)


@cli.command()
@click.argument("hosts", nargs=-1)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
def tls(hosts: tuple[str, ...], concurrency: int, fmt: str) -> None:
    if not hosts:
        stdin = click.get_text_stream("stdin")

        if not stdin.isatty():
            hosts = tuple(line.strip() for line in stdin if line.strip())

    if not hosts:
        raise click.UsageError("Provide hosts as arguments or via stdin.")

    asyncio.run(_tls(hosts=hosts, concurrency=concurrency, fmt=fmt))


async def _tls(*, hosts: tuple[str, ...], concurrency: int, fmt: str) -> None:
    checker = TlsChecker(
        checks=[
            TlsVersionDeprecated(),
            TlsVersionOutdated(),
            TlsCertExpired(),
            TlsCertSelfSigned(),
            TlsCertMismatched(),
            TlsCertRevoked(),
            TlsCertUntrusted(),
            TlsCipherWeak(),
        ],
        concurrency=concurrency,
    )

    with _formatters[fmt]() as formatter:
        async for host_finding in checker.run(hosts):
            formatter.emit(host_finding)
