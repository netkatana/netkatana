import asyncio
import logging
from collections.abc import AsyncIterator, Sequence

import httpx
from httpx import AsyncClient
from pydantic import ValidationError

from netkatana.models import AbstractHttpCheck, AbstractTlsCheck, Finding, HostFinding, TlsResult

_logger = logging.getLogger(__name__)


class HttpChecker:
    def __init__(
        self,
        checks: list[AbstractHttpCheck],
        client: AsyncClient,
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
            except httpx.TransportError as e:
                _logger.warning("%s: %s", host, e)
                return []

        results = await asyncio.gather(*(c.check(response) for c in self._checks))
        findings: list[Finding] = [f for findings in results for f in findings]

        return [HostFinding(host=host, finding=f) for f in findings]


class TlsChecker:
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
            proc.stdin.write("\n".join(hosts).encode())
            await proc.stdin.drain()
            proc.stdin.close()

        write_task = asyncio.create_task(_write_stdin())

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
