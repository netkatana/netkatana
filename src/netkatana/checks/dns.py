from netkatana.checks.config import get_detail, get_severity
from netkatana.types import AbstractDnsCheck, DnsResult, Finding, Severity


class SpfMissing(AbstractDnsCheck):
    _code = "dns_spf_missing"

    async def check(self, result: DnsResult) -> list[Finding]:
        if any(record for record in result.txt if record.startswith("v=spf1")):
            return [
                Finding(
                    code=self._code, severity=Severity.PASS, title="SPF record present", detail=get_detail(self._code)
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=get_severity(self._code),
                title="SPF record missing",
                detail=get_detail(self._code),
            )
        ]


class SpfPermissive(AbstractDnsCheck):
    _code = "dns_spf_permissive"

    async def check(self, result: DnsResult) -> list[Finding]:
        spf_records = [record for record in result.txt if record.startswith("v=spf1")]

        if not spf_records:
            return []

        findings = []
        for record in spf_records:
            if record.rstrip().endswith("+all"):
                findings.append(
                    Finding(
                        code=self._code,
                        severity=get_severity(self._code),
                        title="SPF record allows all senders (+all)",
                        detail=get_detail(self._code),
                        metadata={"record": record},
                    )
                )
            else:
                findings.append(
                    Finding(
                        code=self._code,
                        severity=Severity.PASS,
                        title="SPF record does not allow all senders",
                        detail=get_detail(self._code),
                        metadata={"record": record},
                    )
                )

        return findings


class DmarcMissing(AbstractDnsCheck):
    _code = "dns_dmarc_missing"

    async def check(self, result: DnsResult) -> list[Finding]:
        if any(record for record in result.dmarc_txt if record.startswith("v=DMARC1")):
            return [
                Finding(
                    code=self._code, severity=Severity.PASS, title="DMARC record present", detail=get_detail(self._code)
                )
            ]

        return [
            Finding(
                code=self._code,
                severity=get_severity(self._code),
                title="DMARC record missing",
                detail=get_detail(self._code),
            )
        ]
