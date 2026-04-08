import asyncio
import logging
from collections.abc import AsyncIterator, Sequence

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
    HostFinding,
    HttpRule,
    Severity,
    TlsResult,
    TlsRule,
)

_logger = logging.getLogger(__name__)


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

    async def check_hosts(self, hosts: Sequence[str]) -> AsyncIterator[HostFinding]:
        tasks = [asyncio.create_task(self.check_host(host)) for host in hosts]

        for done in asyncio.as_completed(tasks):
            for host_findings in await done:
                yield host_findings

    async def check_host(self, host: str) -> list[HostFinding]:
        async with self._semaphore:
            try:
                response = await self._client.get(f"https://{host}")
            except RedirectError as e:
                _logger.warning("%s: %r", host, e)
                response = e.response
            except httpx.TransportError as e:
                _logger.warning("%s: %r", host, e)
                return []

        return await self._run_rules(host, response)

    async def _run_rules(self, host: str, response: Response) -> list[HostFinding]:
        results = await asyncio.gather(*(self._run_rule(host, rule, response) for rule in self._rules))
        return [hf for findings in results for hf in findings]

    async def _run_rule(self, host: str, rule: HttpRule, response: Response) -> list[HostFinding]:
        try:
            message = await rule.validator(response)
        except ValidationErrors as e:
            return [self._make_finding(host, rule, error) for error in e.errors]
        except ValidationError as e:
            return [self._make_finding(host, rule, e)]
        if message is None:
            return []
        return [
            HostFinding(
                host=host,
                finding=Finding(code=rule.code, severity=Severity.PASS, title=message, detail=rule.detail),
            )
        ]

    def _make_finding(self, host: str, rule: HttpRule, error: ValidationError) -> HostFinding:
        return HostFinding(
            host=host,
            finding=Finding(
                code=rule.code,
                severity=rule.severity,
                title=error.message,
                detail=rule.detail,
                metadata=error.metadata,
            ),
        )


class TlsScanner:
    def __init__(self, rules: list[TlsRule], concurrency: int = 10) -> None:
        self._rules = rules
        self._concurrency = concurrency

    async def run(self, hosts: Sequence[str]) -> AsyncIterator[HostFinding]:
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
            for host_finding in await self._run_rules(result.host, result):
                yield host_finding

        await write_task
        await proc.wait()

    async def _run_rules(self, host: str, result: TlsResult) -> list[HostFinding]:
        findings = await asyncio.gather(*(self._run_rule(host, rule, result) for rule in self._rules))
        return [hf for group in findings for hf in group]

    async def _run_rule(self, host: str, rule: TlsRule, result: TlsResult) -> list[HostFinding]:
        try:
            message = await rule.validator(result)
        except ValidationErrors as e:
            return [self._make_finding(host, rule, error) for error in e.errors]
        except ValidationError as e:
            return [self._make_finding(host, rule, e)]
        if message is None:
            return []
        return [
            HostFinding(
                host=host,
                finding=Finding(code=rule.code, severity=Severity.PASS, title=message, detail=rule.detail),
            )
        ]

    def _make_finding(self, host: str, rule: TlsRule, error: ValidationError) -> HostFinding:
        return HostFinding(
            host=host,
            finding=Finding(
                code=rule.code,
                severity=rule.severity,
                title=error.message,
                detail=rule.detail,
                metadata=error.metadata,
            ),
        )


class DnsScanner:
    def __init__(self, rules: list[DnsRule], concurrency: int = 10) -> None:
        self._rules = rules
        self._semaphore = asyncio.Semaphore(concurrency)

    async def run(self, domains: Sequence[str]) -> AsyncIterator[HostFinding]:
        tasks = [asyncio.create_task(self._check_domain(domain)) for domain in domains]
        for done in asyncio.as_completed(tasks):
            for host_finding in await done:
                yield host_finding

    async def _check_domain(self, domain: str) -> list[HostFinding]:
        async with self._semaphore:
            txt = await self._query_txt(domain)
            dmarc_txt = await self._query_txt(f"_dmarc.{domain}")

        result = DnsResult(domain=domain, txt=txt, dmarc_txt=dmarc_txt)
        return await self._run_rules(domain, result)

    async def _run_rules(self, domain: str, result: DnsResult) -> list[HostFinding]:
        findings = await asyncio.gather(*(self._run_rule(domain, rule, result) for rule in self._rules))
        return [hf for group in findings for hf in group]

    async def _run_rule(self, domain: str, rule: DnsRule, result: DnsResult) -> list[HostFinding]:
        try:
            message = await rule.validator(result)
        except ValidationErrors as e:
            return [self._make_finding(domain, rule, error) for error in e.errors]
        except ValidationError as e:
            return [self._make_finding(domain, rule, e)]
        if message is None:
            return []
        return [
            HostFinding(
                host=domain,
                finding=Finding(code=rule.code, severity=Severity.PASS, title=message, detail=rule.detail),
            )
        ]

    def _make_finding(self, domain: str, rule: DnsRule, error: ValidationError) -> HostFinding:
        return HostFinding(
            host=domain,
            finding=Finding(
                code=rule.code,
                severity=rule.severity,
                title=error.message,
                detail=rule.detail,
                metadata=error.metadata,
            ),
        )

    async def _query_txt(self, name: str) -> list[str]:
        try:
            answer = await dns.asyncresolver.resolve(name, "TXT")
            return [b"".join(rdata.strings).decode() for rdata in answer]
        except dns.exception.DNSException as e:
            _logger.debug("%s TXT: %r", name, e)
            return []
