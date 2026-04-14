import asyncio
import logging
from collections.abc import AsyncIterator, Sequence
from itertools import chain
from typing import TypeVar

import dns.asyncresolver
import dns.exception
import httpx

from netkatana.exceptions import ValidationError, ValidationErrors
from netkatana.http import Client, RedirectError
from netkatana.tls import TlsxRunner
from netkatana.types import (
    DnsResult,
    DnsRule,
    Finding,
    HttpRule,
    Rule,
    Severity,
    TlsRule,
)

_logger = logging.getLogger(__name__)
T = TypeVar("T")

_HTTPS_FAILED_EXTENSION = "netkatana.https.failed"


def _make_finding(target: str, rule: Rule[T], error: ValidationError) -> Finding:
    return Finding(
        host=target,
        code=rule.code,
        severity=rule.severity,
        message=error.message,
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

    return [Finding(host=target, code=rule.code, severity=Severity.PASS, message=message, detail=rule.detail)]


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

    async def scan(self, targets: Sequence[str]) -> AsyncIterator[Finding]:
        tasks = [asyncio.create_task(self._scan_target(target)) for target in targets]

        for completed_task in asyncio.as_completed(tasks):
            for finding in await completed_task:
                yield finding

    async def _scan_target(self, target: str) -> list[Finding]:
        try:
            response = await self._get_response(f"https://{target}")
            response.extensions[_HTTPS_FAILED_EXTENSION] = False
            return await _run_rules(target, self._rules, response)
        except httpx.TransportError as e:
            _logger.debug("%s HTTPS: %r", target, e)
            https_error = e

        try:
            response = await self._get_response(f"http://{target}")
        except httpx.TransportError as e:
            _logger.warning("%s unreachable over HTTPS and HTTP: HTTPS=%r HTTP=%r", target, https_error, e)
            return []

        response.extensions[_HTTPS_FAILED_EXTENSION] = True
        return await _run_rules(target, self._rules, response)

    async def _get_response(self, url: str) -> httpx.Response:
        async with self._semaphore:
            try:
                return await self._client.get(url)
            except RedirectError as e:
                _logger.warning("%s: %r", url, e)
                return e.response


class TlsScanner:
    def __init__(self, rules: list[TlsRule], concurrency: int = 10, runner: TlsxRunner | None = None) -> None:
        self._rules = rules
        self._runner = runner or TlsxRunner(concurrency)

    async def scan(self, targets: Sequence[str]) -> AsyncIterator[Finding]:
        async for result in self._runner.run(targets):
            for finding in await _run_rules(result.host, self._rules, result):
                yield finding


class DnsScanner:
    def __init__(self, rules: list[DnsRule], concurrency: int = 10) -> None:
        self._rules = rules
        self._semaphore = asyncio.Semaphore(concurrency)

    async def scan(self, targets: Sequence[str]) -> AsyncIterator[Finding]:
        tasks = [asyncio.create_task(self._scan_target(target)) for target in targets]
        for completed_task in asyncio.as_completed(tasks):
            for finding in await completed_task:
                yield finding

    async def _scan_target(self, target: str) -> list[Finding]:
        async with self._semaphore:
            txt = await self._query_txt(target)
            dmarc_txt = await self._query_txt(f"_dmarc.{target}")

        result = DnsResult(domain=target, txt=txt, dmarc_txt=dmarc_txt)
        return await _run_rules(target, self._rules, result)

    async def _query_txt(self, name: str) -> list[str]:
        try:
            answer = await dns.asyncresolver.resolve(name, "TXT")
            return [b"".join(rdata.strings).decode() for rdata in answer]
        except dns.exception.DNSException as e:
            _logger.debug("%s TXT: %r", name, e)
            return []
