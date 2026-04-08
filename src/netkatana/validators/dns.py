from netkatana.exceptions import ValidationError, ValidationErrors
from netkatana.types import DnsResult


async def spf_missing(result: DnsResult) -> str | None:
    if any(record for record in result.txt if record.startswith("v=spf1")):
        return "SPF record present"

    raise ValidationError("SPF record missing")


async def spf_multiple(result: DnsResult) -> str | None:
    spf_records = [record for record in result.txt if record.startswith("v=spf1")]

    if len(spf_records) <= 1:
        return None

    raise ValidationError("Multiple SPF records found", metadata={"count": str(len(spf_records))})


async def spf_permissive(result: DnsResult) -> str | None:
    spf_records = [record for record in result.txt if record.startswith("v=spf1")]

    if not spf_records:
        return None

    errors = [
        ValidationError("SPF record allows all senders (+all)", metadata={"record": record})
        for record in spf_records
        if record.rstrip().endswith("+all")
    ]
    if errors:
        raise ValidationErrors(errors)

    return "SPF records do not allow all senders"


async def dmarc_missing(result: DnsResult) -> str | None:
    if any(record for record in result.dmarc_txt if record.startswith("v=DMARC1")):
        return "DMARC record present"

    raise ValidationError("DMARC record missing")


async def dmarc_multiple(result: DnsResult) -> str | None:
    dmarc_records = [record for record in result.dmarc_txt if record.startswith("v=DMARC1")]

    if len(dmarc_records) <= 1:
        return None

    raise ValidationError("Multiple DMARC records found", metadata={"count": str(len(dmarc_records))})
