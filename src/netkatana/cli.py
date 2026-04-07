import asyncio
import logging

import click
from rich.console import Console
from rich.logging import RichHandler

from netkatana.checks.dns import DmarcMissing, SpfMissing, SpfPermissive
from netkatana.checks.http.headers import (
    ContentSecurityPolicyMissing,
    StrictTransportSecurityIncludeSubdomainsMissing,
    StrictTransportSecurityInvalid,
    StrictTransportSecurityMaxAgeLow,
    StrictTransportSecurityMaxAgeZero,
    StrictTransportSecurityMissing,
    StrictTransportSecurityPreloadNotEligible,
)
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
from netkatana.http import Client
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
            checks=[
                StrictTransportSecurityMissing(),
                StrictTransportSecurityInvalid(),
                StrictTransportSecurityMaxAgeZero(),
                StrictTransportSecurityMaxAgeLow(),
                StrictTransportSecurityIncludeSubdomainsMissing(),
                StrictTransportSecurityPreloadNotEligible(),
                ContentSecurityPolicyMissing(),
            ],
            client=client,
            concurrency=concurrency,
        )

        with _formatters[fmt](show_passed=show_passed) as formatter:
            async for host_finding in scanner.check_hosts(hosts):
                formatter.emit(host_finding)


@cli.command()
@click.argument("hosts", nargs=-1, callback=_get_hosts)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
@click.option("--show-passed", is_flag=True, default=False)
def tls(hosts: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    asyncio.run(_tls(hosts=hosts, concurrency=concurrency, fmt=fmt, show_passed=show_passed))


async def _tls(*, hosts: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    scanner = TlsScanner(
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

    with _formatters[fmt](show_passed=show_passed) as formatter:
        async for host_finding in scanner.run(hosts):
            formatter.emit(host_finding)


@cli.command()
@click.argument("domains", nargs=-1, callback=_get_hosts)
@click.option("-c", "--concurrency", default=10, show_default=True, type=int)
@click.option("-f", "--format", "fmt", default="verbose", show_default=True, type=click.Choice(_formatters.keys()))
@click.option("--show-passed", is_flag=True, default=False)
def dns(domains: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    asyncio.run(_dns(domains=domains, concurrency=concurrency, fmt=fmt, show_passed=show_passed))


async def _dns(*, domains: list[str], concurrency: int, fmt: str, show_passed: bool) -> None:
    scanner = DnsScanner(
        checks=[SpfMissing(), SpfPermissive(), DmarcMissing()],
        concurrency=concurrency,
    )

    with _formatters[fmt](show_passed=show_passed) as formatter:
        async for host_finding in scanner.run(domains):
            formatter.emit(host_finding)
