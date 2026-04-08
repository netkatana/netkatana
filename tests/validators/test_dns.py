import pytest

from netkatana.exceptions import ValidationError, ValidationErrors
from netkatana.types import DnsResult
from netkatana.validators.dns import dmarc_missing, dmarc_multiple, spf_missing, spf_multiple, spf_permissive


@pytest.mark.asyncio
async def test_spf_missing_missing():
    result = DnsResult(domain="example.com", txt=[], dmarc_txt=[])

    with pytest.raises(ValidationError) as exc_info:
        await spf_missing(result)

    assert exc_info.value.message == "SPF record missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_spf_missing_present():
    result = DnsResult(domain="example.com", txt=["v=spf1 include:sendgrid.net ~all"], dmarc_txt=[])

    message = await spf_missing(result)

    assert message == "SPF record present"


@pytest.mark.asyncio
async def test_spf_multiple_no_spf():
    result = DnsResult(domain="example.com", txt=[], dmarc_txt=[])

    message = await spf_multiple(result)

    assert message is None


@pytest.mark.asyncio
async def test_spf_multiple_single_spf():
    result = DnsResult(domain="example.com", txt=["v=spf1 -all"], dmarc_txt=[])

    message = await spf_multiple(result)

    assert message is None


@pytest.mark.asyncio
async def test_spf_multiple_multiple_spf():
    result = DnsResult(domain="example.com", txt=["v=spf1 -all", "v=spf1 include:sendgrid.net ~all"], dmarc_txt=[])

    with pytest.raises(ValidationError) as exc_info:
        await spf_multiple(result)

    assert exc_info.value.message == "Multiple SPF records found"
    assert exc_info.value.metadata == {"count": "2"}


@pytest.mark.asyncio
async def test_spf_permissive_no_spf():
    result = DnsResult(domain="example.com", txt=[], dmarc_txt=[])

    message = await spf_permissive(result)

    assert message is None


@pytest.mark.asyncio
async def test_spf_permissive_permissive():
    result = DnsResult(domain="example.com", txt=["v=spf1 +all"], dmarc_txt=[])

    with pytest.raises(ValidationErrors) as exc_info:
        await spf_permissive(result)

    assert [error.message for error in exc_info.value.errors] == ["SPF record allows all senders (+all)"]
    assert [error.metadata for error in exc_info.value.errors] == [{"record": "v=spf1 +all"}]


@pytest.mark.asyncio
async def test_spf_permissive_safe():
    result = DnsResult(domain="example.com", txt=["v=spf1 include:sendgrid.net -all"], dmarc_txt=[])

    message = await spf_permissive(result)

    assert message == "SPF records do not allow all senders"


@pytest.mark.asyncio
async def test_spf_permissive_multiple_permissive_records():
    result = DnsResult(domain="example.com", txt=["v=spf1 +all", "v=spf1 mx +all"], dmarc_txt=[])

    with pytest.raises(ValidationErrors) as exc_info:
        await spf_permissive(result)

    assert [error.message for error in exc_info.value.errors] == [
        "SPF record allows all senders (+all)",
        "SPF record allows all senders (+all)",
    ]
    assert [error.metadata for error in exc_info.value.errors] == [
        {"record": "v=spf1 +all"},
        {"record": "v=spf1 mx +all"},
    ]


@pytest.mark.asyncio
async def test_dmarc_missing_missing():
    result = DnsResult(domain="example.com", txt=[], dmarc_txt=[])

    with pytest.raises(ValidationError) as exc_info:
        await dmarc_missing(result)

    assert exc_info.value.message == "DMARC record missing"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_dmarc_missing_present():
    result = DnsResult(domain="example.com", txt=[], dmarc_txt=["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])

    message = await dmarc_missing(result)

    assert message == "DMARC record present"


@pytest.mark.asyncio
async def test_dmarc_multiple_no_dmarc():
    result = DnsResult(domain="example.com", txt=[], dmarc_txt=[])

    message = await dmarc_multiple(result)

    assert message is None


@pytest.mark.asyncio
async def test_dmarc_multiple_single_dmarc():
    result = DnsResult(domain="example.com", txt=[], dmarc_txt=["v=DMARC1; p=reject"])

    message = await dmarc_multiple(result)

    assert message is None


@pytest.mark.asyncio
async def test_dmarc_multiple_multiple_dmarc():
    result = DnsResult(domain="example.com", txt=[], dmarc_txt=["v=DMARC1; p=reject", "v=DMARC1; p=quarantine"])

    with pytest.raises(ValidationError) as exc_info:
        await dmarc_multiple(result)

    assert exc_info.value.message == "Multiple DMARC records found"
    assert exc_info.value.metadata == {"count": "2"}
