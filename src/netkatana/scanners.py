import asyncio
import logging
from collections.abc import AsyncIterator, Sequence

import dns.asyncresolver
import dns.exception
import httpx
from pydantic import ValidationError

from netkatana.http import Client, RedirectError
from netkatana.types import (
    AbstractDnsCheck,
    AbstractHttpCheck,
    AbstractTlsCheck,
    DnsResult,
    Finding,
    HostFinding,
    TlsResult,
)

_logger = logging.getLogger(__name__)


class HttpScanner:
    def __init__(
        self,
        checks: list[AbstractHttpCheck],
        client: Client,
        concurrency: int = 10,
    ) -> None:
        self._checks = checks
        self._client = client
        self._semaphore = asyncio.Semaphore(concurrency)

    async def check_hosts(self, hosts: Sequence[str]) -> AsyncIterator[HostFinding]:
        tasks = [asyncio.create_task(self.check_host(h)) for h in hosts]
        for done in asyncio.as_completed(tasks):
            host_findings = await done
            for host_finding in host_findings:
                yield host_finding

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

        results = await asyncio.gather(*(c.check(response) for c in self._checks))
        findings: list[Finding] = [f for findings in results for f in findings]

        return [HostFinding(host=host, finding=f) for f in findings]


class TlsScanner:
    def __init__(self, checks: list[AbstractTlsCheck], concurrency: int = 10) -> None:
        self._checks = checks
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
            except ValidationError:
                _logger.warning("Failed to parse tlsx output: %s", line)
                continue
            check_results = await asyncio.gather(*(c.check(result) for c in self._checks))
            for finding in [f for findings in check_results for f in findings]:
                yield HostFinding(host=result.host, finding=finding)

        await write_task
        await proc.wait()


class DnsScanner:
    def __init__(self, checks: list[AbstractDnsCheck], concurrency: int = 10) -> None:
        self._checks = checks
        self._semaphore = asyncio.Semaphore(concurrency)

    async def run(self, domains: Sequence[str]) -> AsyncIterator[HostFinding]:
        tasks = [asyncio.create_task(self._check_domain(d)) for d in domains]
        for done in asyncio.as_completed(tasks):
            for hf in await done:
                yield hf

    async def _check_domain(self, domain: str) -> list[HostFinding]:
        async with self._semaphore:
            txt = await self._query_txt(domain)
            dmarc_txt = await self._query_txt(f"_dmarc.{domain}")

        result = DnsResult(domain=domain, txt=txt, dmarc_txt=dmarc_txt)
        check_results = await asyncio.gather(*(c.check(result) for c in self._checks))
        findings: list[Finding] = [f for findings in check_results for f in findings]
        return [HostFinding(host=domain, finding=f) for f in findings]

    async def _query_txt(self, name: str) -> list[str]:
        try:
            answer = await dns.asyncresolver.resolve(name, "TXT")
            return [b"".join(rdata.strings).decode() for rdata in answer]
        except dns.exception.DNSException as e:
            _logger.debug("%s TXT: %r", name, e)
            return []
