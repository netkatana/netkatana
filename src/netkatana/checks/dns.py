from netkatana.types import AbstractDnsCheck, DnsResult, Finding, Severity


class SpfMissing(AbstractDnsCheck):
    _code = "dns_spf_missing"
    _detail = "An SPF TXT record lists the servers authorized to send email for this domain; without it, mail servers cannot verify sender authenticity."

    async def check(self, result: DnsResult) -> list[Finding]:
        if any(record for record in result.txt if record.startswith("v=spf1")):
            return [Finding(code=self._code, severity=Severity.PASS, title="SPF record present", detail=self._detail)]

        return [Finding(code=self._code, severity=Severity.NOTICE, title="SPF record missing", detail=self._detail)]


class SpfPermissive(AbstractDnsCheck):
    _code = "dns_spf_permissive"
    _detail = "The '+all' mechanism in an SPF record authorizes any server on the internet to send email for this domain, negating anti-spoofing protection."

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
                        severity=Severity.CRITICAL,
                        title="SPF record allows all senders (+all)",
                        detail=self._detail,
                        metadata={"record": record},
                    )
                )
            else:
                findings.append(
                    Finding(
                        code=self._code,
                        severity=Severity.PASS,
                        title="SPF record does not allow all senders",
                        detail=self._detail,
                        metadata={"record": record},
                    )
                )

        return findings


class DmarcMissing(AbstractDnsCheck):
    _code = "dns_dmarc_missing"
    _detail = "A DMARC record at '_dmarc.<domain>' specifies how mail receivers should handle messages that fail SPF or DKIM checks."

    async def check(self, result: DnsResult) -> list[Finding]:
        if any(record for record in result.dmarc_txt if record.startswith("v=DMARC1")):
            return [Finding(code=self._code, severity=Severity.PASS, title="DMARC record present", detail=self._detail)]

        return [Finding(code=self._code, severity=Severity.NOTICE, title="DMARC record missing", detail=self._detail)]
