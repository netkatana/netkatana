import asyncio

import click
from httpx import AsyncClient

from netkatana.checkers import Checker
from netkatana.checks.http.headers import ContentSecurityPolicyMissing, StrictTransportSecurityMissing
from netkatana.formatters import AbstractFormatter, JsonFormatter, JsonlFormatter, TableFormatter, VerboseFormatter

_formatters: dict[str, type[AbstractFormatter]] = {
    "verbose": VerboseFormatter,
    "jsonl": JsonlFormatter,
    "json": JsonFormatter,
    "table": TableFormatter,
}


@click.group()
def cli() -> None:
    pass


@cli.command()
@click.argument("hosts", nargs=-1)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
def http(hosts: tuple[str, ...], concurrency: int, fmt: str) -> None:
    asyncio.run(_http(hosts=hosts, concurrency=concurrency, fmt=fmt))


async def _http(*, hosts: tuple[str, ...], concurrency: int, fmt: str) -> None:
    async with AsyncClient(verify=False, follow_redirects=True) as client:
        checker = Checker(
            checks=[StrictTransportSecurityMissing(), ContentSecurityPolicyMissing()],
            client=client,
            concurrency=concurrency,
        )

        with _formatters[fmt]() as formatter:
            async for finding in checker.run(hosts):
                formatter.emit(finding)
