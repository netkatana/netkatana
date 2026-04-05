import asyncio
from collections.abc import AsyncIterator, Sequence

from httpx import AsyncClient

from netkatana.models import AbstractCheck, Finding


class Checker:
    def __init__(
        self,
        checks: list[AbstractCheck],
        client: AsyncClient,
        concurrency: int = 10,
    ) -> None:
        self._checks = checks
        self._client = client
        self._semaphore = asyncio.Semaphore(concurrency)

    async def run(self, hosts: Sequence[str]) -> AsyncIterator[Finding]:
        tasks = [asyncio.create_task(self._check_host(h)) for h in hosts]
        for done in asyncio.as_completed(tasks):
            findings = await done
            for finding in findings:
                yield finding

    async def _check_host(self, host: str) -> list[Finding]:
        async with self._semaphore:
            response = await self._client.get(host)
        results = await asyncio.gather(*(c.check(response) for c in self._checks))
        findings = [f for findings in results for f in findings]
        for finding in findings:
            finding.host = host
        return findings
