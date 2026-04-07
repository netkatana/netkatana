import pytest

from netkatana.checks.dns import DmarcMissing, SpfMissing, SpfPermissive
from netkatana.models import DnsResult, Severity


class TestSpfMissing:
    @pytest.mark.asyncio
    async def test_missing(self):
        result = DnsResult(domain="example.com", txt=[], dmarc_txt=[])
        findings = await SpfMissing().check(result)

        assert len(findings) == 1
        assert findings[0].code == "dns_spf_missing"
        assert findings[0].severity == Severity.NOTICE

    @pytest.mark.asyncio
    async def test_present(self):
        result = DnsResult(domain="example.com", txt=["v=spf1 include:sendgrid.net ~all"], dmarc_txt=[])
        findings = await SpfMissing().check(result)

        assert len(findings) == 1
        assert findings[0].code == "dns_spf_missing"
        assert findings[0].severity == Severity.PASS


class TestSpfPermissive:
    @pytest.mark.asyncio
    async def test_no_spf_returns_empty(self):
        result = DnsResult(domain="example.com", txt=[], dmarc_txt=[])
        findings = await SpfPermissive().check(result)

        assert findings == []

    @pytest.mark.asyncio
    async def test_permissive(self):
        result = DnsResult(domain="example.com", txt=["v=spf1 +all"], dmarc_txt=[])
        findings = await SpfPermissive().check(result)

        assert len(findings) == 1
        assert findings[0].code == "dns_spf_permissive"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].metadata["record"] == "v=spf1 +all"

    @pytest.mark.asyncio
    async def test_softfail(self):
        result = DnsResult(domain="example.com", txt=["v=spf1 include:sendgrid.net ~all"], dmarc_txt=[])
        findings = await SpfPermissive().check(result)

        assert len(findings) == 1
        assert findings[0].code == "dns_spf_permissive"
        assert findings[0].severity == Severity.PASS
        assert findings[0].metadata["record"] == "v=spf1 include:sendgrid.net ~all"

    @pytest.mark.asyncio
    async def test_hardfail(self):
        result = DnsResult(domain="example.com", txt=["v=spf1 include:sendgrid.net -all"], dmarc_txt=[])
        findings = await SpfPermissive().check(result)

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS

    @pytest.mark.asyncio
    async def test_multiple_records(self):
        result = DnsResult(domain="example.com", txt=["v=spf1 -all", "v=spf1 +all"], dmarc_txt=[])
        findings = await SpfPermissive().check(result)

        assert len(findings) == 2
        assert findings[0].severity == Severity.PASS
        assert findings[1].severity == Severity.CRITICAL


class TestDmarcMissing:
    @pytest.mark.asyncio
    async def test_missing(self):
        result = DnsResult(domain="example.com", txt=[], dmarc_txt=[])
        findings = await DmarcMissing().check(result)

        assert len(findings) == 1
        assert findings[0].code == "dns_dmarc_missing"
        assert findings[0].severity == Severity.NOTICE

    @pytest.mark.asyncio
    async def test_present(self):
        result = DnsResult(domain="example.com", txt=[], dmarc_txt=["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])
        findings = await DmarcMissing().check(result)

        assert len(findings) == 1
        assert findings[0].code == "dns_dmarc_missing"
        assert findings[0].severity == Severity.PASS
