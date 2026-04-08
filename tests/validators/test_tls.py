import pytest

from netkatana.exceptions import ValidationError
from netkatana.types import TlsResult
from netkatana.validators.tls import (
    tls_cert_expired,
    tls_cert_mismatched,
    tls_cert_revoked,
    tls_cert_self_signed,
    tls_cert_untrusted,
    tls_cipher_weak,
    tls_version_deprecated,
    tls_version_outdated,
)


@pytest.mark.asyncio
async def test_tls_version_deprecated_deprecated():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls10", cipher="")

    with pytest.raises(ValidationError) as exc_info:
        await tls_version_deprecated(result)

    assert exc_info.value.message == "Deprecated TLS version in use (TLS10)"
    assert exc_info.value.metadata == {"tls_version": "tls10"}


@pytest.mark.asyncio
async def test_tls_version_deprecated_current():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="")

    message = await tls_version_deprecated(result)

    assert message == "TLS version is not deprecated"


@pytest.mark.asyncio
async def test_tls_version_outdated_outdated():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls12", cipher="")

    with pytest.raises(ValidationError) as exc_info:
        await tls_version_outdated(result)

    assert exc_info.value.message == "Outdated TLS version in use (TLS 1.2)"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_tls_version_outdated_current():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="")

    message = await tls_version_outdated(result)

    assert message == "TLS version is current"


@pytest.mark.asyncio
async def test_tls_cert_expired_expired():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="", expired=True)

    with pytest.raises(ValidationError) as exc_info:
        await tls_cert_expired(result)

    assert exc_info.value.message == "Certificate is expired"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_tls_cert_expired_not_expired():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="")

    message = await tls_cert_expired(result)

    assert message == "Certificate is not expired"


@pytest.mark.asyncio
async def test_tls_cert_self_signed_self_signed():
    result = TlsResult(
        host="example.com",
        port="443",
        ip="127.0.0.1",
        tls_version="tls13",
        cipher="",
        self_signed=True,
    )

    with pytest.raises(ValidationError) as exc_info:
        await tls_cert_self_signed(result)

    assert exc_info.value.message == "Certificate is self-signed"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_tls_cert_self_signed_ca_signed():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="")

    message = await tls_cert_self_signed(result)

    assert message == "Certificate is CA-signed"


@pytest.mark.asyncio
async def test_tls_cert_mismatched_mismatched():
    result = TlsResult(
        host="example.com",
        port="443",
        ip="127.0.0.1",
        tls_version="tls13",
        cipher="",
        mismatched=True,
    )

    with pytest.raises(ValidationError) as exc_info:
        await tls_cert_mismatched(result)

    assert exc_info.value.message == "Certificate hostname mismatch"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_tls_cert_mismatched_matches():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="")

    message = await tls_cert_mismatched(result)

    assert message == "Certificate hostname matches"


@pytest.mark.asyncio
async def test_tls_cert_revoked_revoked():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="", revoked=True)

    with pytest.raises(ValidationError) as exc_info:
        await tls_cert_revoked(result)

    assert exc_info.value.message == "Certificate has been revoked"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_tls_cert_revoked_not_revoked():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="")

    message = await tls_cert_revoked(result)

    assert message == "Certificate is not revoked"


@pytest.mark.asyncio
async def test_tls_cert_untrusted_untrusted():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="", untrusted=True)

    with pytest.raises(ValidationError) as exc_info:
        await tls_cert_untrusted(result)

    assert exc_info.value.message == "Certificate is not trusted"
    assert exc_info.value.metadata == {}


@pytest.mark.asyncio
async def test_tls_cert_untrusted_trusted():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="")

    message = await tls_cert_untrusted(result)

    assert message == "Certificate is trusted"


@pytest.mark.asyncio
async def test_tls_cipher_weak_no_cipher():
    result = TlsResult(host="example.com", port="443", ip="127.0.0.1", tls_version="tls13", cipher="")

    message = await tls_cipher_weak(result)

    assert message is None


@pytest.mark.asyncio
async def test_tls_cipher_weak_weak():
    result = TlsResult(
        host="example.com",
        port="443",
        ip="127.0.0.1",
        tls_version="tls13",
        cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    )

    with pytest.raises(ValidationError) as exc_info:
        await tls_cipher_weak(result)

    assert exc_info.value.message == "Weak cipher negotiated (TLS_RSA_WITH_3DES_EDE_CBC_SHA)"
    assert exc_info.value.metadata == {"cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}


@pytest.mark.asyncio
async def test_tls_cipher_weak_strong():
    result = TlsResult(
        host="example.com",
        port="443",
        ip="127.0.0.1",
        tls_version="tls13",
        cipher="TLS_AES_256_GCM_SHA384",
    )

    message = await tls_cipher_weak(result)

    assert message == "Cipher suite is strong"
