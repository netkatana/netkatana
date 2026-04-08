import asyncio
import logging
from collections.abc import AsyncIterator, Sequence
from itertools import chain
from typing import TypeVar

import dns.asyncresolver
import dns.exception
import httpx
from httpx import Response
from pydantic import ValidationError as PydanticValidationError

from netkatana.exceptions import ValidationError, ValidationErrors
from netkatana.http import Client, RedirectError
from netkatana.types import (
    DnsResult,
    DnsRule,
    Finding,
    HttpRule,
    Rule,
    Severity,
    TlsResult,
    TlsRule,
)

_logger = logging.getLogger(__name__)
T = TypeVar("T")


def _make_finding(target: str, rule: Rule[object], error: ValidationError) -> Finding:
    return Finding(
        host=target,
        code=rule.code,
        severity=rule.severity,
        title=error.message,
        detail=rule.detail,
        metadata=error.metadata,
    )


async def _run_rule(target: str, rule: Rule[T], result: T) -> list[Finding]:
    try:
        message = await rule.validator(result)
    except ValidationErrors as e:
        return [_make_finding(target, rule, error) for error in e.errors]
    except ValidationError as e:
        return [_make_finding(target, rule, e)]

    if message is None:
        return []

    return [Finding(host=target, code=rule.code, severity=Severity.PASS, title=message, detail=rule.detail)]


async def _run_rules(target: str, rules: Sequence[Rule[T]], result: T) -> list[Finding]:
    finding_batches = await asyncio.gather(*(_run_rule(target, rule, result) for rule in rules))
    return list(chain.from_iterable(finding_batches))


class HttpScanner:
    def __init__(
        self,
        rules: list[HttpRule],
        client: Client,
        concurrency: int = 10,
    ) -> None:
        self._rules = rules
        self._client = client
        self._semaphore = asyncio.Semaphore(concurrency)

    async def check_hosts(self, hosts: Sequence[str]) -> AsyncIterator[Finding]:
        tasks = [asyncio.create_task(self.check_host(host)) for host in hosts]

        for done in asyncio.as_completed(tasks):
            for finding in await done:
                yield finding

    async def check_host(self, host: str) -> list[Finding]:
        async with self._semaphore:
            try:
                response = await self._client.get(f"https://{host}")
            except RedirectError as e:
                _logger.warning("%s: %r", host, e)
                response = e.response
            except httpx.TransportError as e:
                _logger.warning("%s: %r", host, e)
                return []

        return await _run_rules(host, self._rules, response)


class TlsScanner:
    def __init__(self, rules: list[TlsRule], concurrency: int = 10) -> None:
        self._rules = rules
        self._concurrency = concurrency

    async def run(self, hosts: Sequence[str]) -> AsyncIterator[Finding]:
        proc = await asyncio.create_subprocess_exec(
            "tlsx",
            "-json",
            "-tls-version",
            "-cipher",
            "-expired",
            "-self-signed",
            "-mismatched",
            "-revoked",
            "-untrusted",
            "-silent",
            "-concurrency",
            str(self._concurrency),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        async def _write_stdin() -> None:
            assert proc.stdin is not None
            proc.stdin.write("\n".join(hosts).encode())
            await proc.stdin.drain()
            proc.stdin.close()

        write_task = asyncio.create_task(_write_stdin())

        assert proc.stdout is not None

        async for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                result = TlsResult.model_validate_json(line)
            except PydanticValidationError:
                _logger.warning("Failed to parse tlsx output: %s", line)
                continue
            for finding in await _run_rules(result.host, self._rules, result):
                yield finding

        await write_task
        await proc.wait()


class DnsScanner:
    def __init__(self, rules: list[DnsRule], concurrency: int = 10) -> None:
        self._rules = rules
        self._semaphore = asyncio.Semaphore(concurrency)

    async def run(self, domains: Sequence[str]) -> AsyncIterator[Finding]:
        tasks = [asyncio.create_task(self._check_domain(domain)) for domain in domains]
        for done in asyncio.as_completed(tasks):
            for finding in await done:
                yield finding

    async def _check_domain(self, domain: str) -> list[Finding]:
        async with self._semaphore:
            txt = await self._query_txt(domain)
            dmarc_txt = await self._query_txt(f"_dmarc.{domain}")

        result = DnsResult(domain=domain, txt=txt, dmarc_txt=dmarc_txt)
        return await _run_rules(domain, self._rules, result)

    async def _query_txt(self, name: str) -> list[str]:
        try:
            answer = await dns.asyncresolver.resolve(name, "TXT")
            return [b"".join(rdata.strings).decode() for rdata in answer]
        except dns.exception.DNSException as e:
            _logger.debug("%s TXT: %r", name, e)
            return []
