from netkatana.models import AbstractDnsCheck, DnsResult, Finding, Severity


class SpfMissing(AbstractDnsCheck):
    _code = "dns_spf_missing"
    _detail = (
        "Without an SPF record, any server can send email claiming to be from this domain. "
        "Add a TXT record like 'v=spf1 include:... ~all' to declare authorized senders."
    )

    async def check(self, result: DnsResult) -> list[Finding]:
        if any(record for record in result.txt if record.startswith("v=spf1")):
            return [Finding(code=self._code, severity=Severity.PASS, title="SPF record present", detail=self._detail)]

        return [Finding(code=self._code, severity=Severity.NOTICE, title="SPF record missing", detail=self._detail)]


class SpfPermissive(AbstractDnsCheck):
    _code = "dns_spf_permissive"
    _detail = (
        "The SPF record ends with '+all', which authorizes every server on the internet to send email "
        "as this domain. Change to '~all' (softfail) or '-all' (fail) to restrict authorized senders."
    )

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
    _detail = (
        "Without a DMARC record at _dmarc.<domain>, there is no policy instructing receivers how to handle "
        "emails that fail SPF/DKIM alignment. Add a TXT record like 'v=DMARC1; p=reject; ...' to enforce protection."
    )

    async def check(self, result: DnsResult) -> list[Finding]:
        if any(record for record in result.dmarc_txt if record.startswith("v=DMARC1")):
            return [Finding(code=self._code, severity=Severity.PASS, title="DMARC record present", detail=self._detail)]

        return [Finding(code=self._code, severity=Severity.NOTICE, title="DMARC record missing", detail=self._detail)]
