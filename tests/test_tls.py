import asyncio

import pytest
from pytest import LogCaptureFixture
from pytest_mock import MockerFixture

from netkatana.tls import TlsxRunner
from netkatana.types import TlsResult


class _FakeStdout:
    def __init__(self, lines: list[bytes]) -> None:
        self._lines = lines

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        if not self._lines:
            raise StopAsyncIteration
        return self._lines.pop(0)


class _FakeStdin:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeProcess:
    def __init__(self, lines: list[bytes]) -> None:
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(lines)
        self.wait = None


@pytest.mark.asyncio
async def test_tlsx_runner_yields_parsed_results(mocker: MockerFixture, caplog: LogCaptureFixture):
    proc = _FakeProcess(
        [
            b'{"host":"example.com","port":"443","ip":"127.0.0.1","tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256"}\n',
            b"not json\n",
            b"\n",
            b'{"host":"example.org","port":"443","ip":"127.0.0.2","tls_version":"tls12","cipher":"ECDHE-RSA-AES256-GCM-SHA384"}\n',
        ]
    )
    proc.wait = mocker.AsyncMock()
    create_subprocess_exec = mocker.patch.object(
        asyncio, "create_subprocess_exec", new=mocker.AsyncMock(return_value=proc)
    )
    runner = TlsxRunner()

    with caplog.at_level("WARNING"):
        results = [result async for result in runner.run(["example.com", "example.org"])]

    assert results == [
        TlsResult(
            host="example.com",
            port="443",
            ip="127.0.0.1",
            tls_version="tls13",
            cipher="TLS_AES_128_GCM_SHA256",
        ),
        TlsResult(
            host="example.org",
            port="443",
            ip="127.0.0.2",
            tls_version="tls12",
            cipher="ECDHE-RSA-AES256-GCM-SHA384",
        ),
    ]
    assert bytes(proc.stdin.buffer) == b"example.com\nexample.org"
    assert proc.stdin.closed is True
    assert "Failed to parse tlsx output: b'not json'" in caplog.text

    create_subprocess_exec.assert_awaited_once_with(
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
        "10",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    proc.wait.assert_awaited_once_with()
