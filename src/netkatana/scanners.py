import asyncio
import logging
from collections.abc import AsyncIterator, Sequence
from itertools import chain
from typing import ClassVar, TypeVar

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
    _https_upgrade_redirect_missing_code: ClassVar[str] = "response_https_upgrade_redirect_missing"

    def __init__(
        self,
        rules: list[HttpRule],
        client: Client,
        concurrency: int = 10,
    ) -> None:
        self._rules = rules
        self._client = client
        self._http_semaphore = asyncio.Semaphore(concurrency)

    async def scan(self, targets: Sequence[str]) -> AsyncIterator[Finding]:
        tasks = [asyncio.create_task(self._scan_target(target)) for target in targets]

        for completed_task in asyncio.as_completed(tasks):
            for finding in await completed_task:
                yield finding

    async def _scan_target(self, target: str) -> list[Finding]:
        if (https_response := await self._get_scheme_response("https", target)) is not None:
            primary_findings = await self._run_primary_rules(target, https_response)

            http_upgrade_response = await self._get_scheme_response("http", target)
            if http_upgrade_response is None:
                return primary_findings

            upgrade_findings = await self._run_upgrade_rules(target, http_upgrade_response)
            return primary_findings + upgrade_findings

        if (http_fallback_response := await self._get_scheme_response("http", target)) is not None:
            http_fallback_response.extensions["netkatana.https.failed"] = True
            return await self._run_primary_rules(target, http_fallback_response)

        return []

    async def _get_scheme_response(self, scheme: str, target: str) -> httpx.Response | None:
        try:
            return await self._get_response(f"{scheme}://{target}")
        except httpx.TransportError as e:
            _logger.debug("%s %s: %r", target, scheme.upper(), e)
            return None

    async def _get_response(self, url: str) -> httpx.Response:
        async with self._http_semaphore:
            try:
                return await self._client.get(url)
            except RedirectError as e:
                _logger.warning("%s: %r", url, e)
                return e.response

    async def _run_primary_rules(self, target: str, response: httpx.Response) -> list[Finding]:
        return await _run_rules(target, self._get_primary_rules(), response)

    async def _run_upgrade_rules(self, target: str, response: httpx.Response) -> list[Finding]:
        return await _run_rules(target, self._get_upgrade_rules(), response)

    def _get_primary_rules(self) -> list[HttpRule]:
        return [rule for rule in self._rules if rule.code != self._https_upgrade_redirect_missing_code]

    def _get_upgrade_rules(self) -> list[HttpRule]:
        return [rule for rule in self._rules if rule.code == self._https_upgrade_redirect_missing_code]


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
