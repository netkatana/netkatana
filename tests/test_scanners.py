import pytest
from pytest_mock import MockerFixture

from netkatana.scanners import TlsScanner
from netkatana.tls import TlsxRunner
from netkatana.types import Rule, Severity, TlsResult


class TestTlsScanner:
    @pytest.mark.asyncio
    async def test_scan_consumes_runner_results(self, mocker: MockerFixture):
        async def _validator(result: TlsResult) -> str | None:
            return f"validated {result.tls_version}"

        async def _fake_run(targets):
            yield TlsResult(
                host="example.com",
                port="443",
                ip="127.0.0.1",
                tls_version="tls13",
                cipher="TLS_AES_128_GCM_SHA256",
            )

        runner = mocker.Mock(spec=TlsxRunner)
        runner.run = mocker.Mock(side_effect=_fake_run)
        scanner = TlsScanner(
            [
                Rule(
                    code="tls-ok",
                    severity=Severity.NOTICE,
                    detail="detail",
                    validator=_validator,
                )
            ],
            runner=runner,
        )

        findings = [finding async for finding in scanner.scan(["example.com"])]

        assert len(findings) == 1
        assert findings[0].host == "example.com"
        assert findings[0].code == "tls-ok"
        assert findings[0].severity is Severity.PASS
        assert findings[0].message == "validated tls13"

        runner.run.assert_called_once_with(["example.com"])
