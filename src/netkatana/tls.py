import asyncio
import logging
from collections.abc import AsyncIterator, Sequence

from pydantic import ValidationError as PydanticValidationError

from netkatana.types import TlsResult

_logger = logging.getLogger(__name__)


class TlsxRunner:
    def __init__(self, concurrency: int = 10) -> None:
        self._concurrency = concurrency

    async def run(self, targets: Sequence[str]) -> AsyncIterator[TlsResult]:
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
            proc.stdin.write("\n".join(targets).encode())
            await proc.stdin.drain()
            proc.stdin.close()

        write_task = asyncio.create_task(_write_stdin())

        assert proc.stdout is not None

        async for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            try:
                yield TlsResult.model_validate_json(line)
            except PydanticValidationError:
                _logger.warning("Failed to parse tlsx output: %s", line)

        await write_task
        await proc.wait()
