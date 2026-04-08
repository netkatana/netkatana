from netkatana.exceptions import ValidationError
from netkatana.types import TlsResult

_DEPRECATED_TLS_VERSIONS = {"ssl30", "tls10", "tls11"}
_OUTDATED_TLS_VERSIONS = {"tls12"}
_WEAK_CIPHER_SUBSTRINGS = (
    "RC4",
    "NULL",
    "EXPORT",
    "_anon_",
    "WITH_DES_",
    "WITH_3DES_",
    "IDEA",
    "SEED",
)


async def tls_version_deprecated(result: TlsResult) -> str | None:
    if result.tls_version not in _DEPRECATED_TLS_VERSIONS:
        return "TLS version is not deprecated"

    raise ValidationError(
        f"Deprecated TLS version in use ({result.tls_version.upper()})",
        metadata={"tls_version": result.tls_version},
    )


async def tls_version_outdated(result: TlsResult) -> str | None:
    if result.tls_version not in _OUTDATED_TLS_VERSIONS:
        return "TLS version is current"

    raise ValidationError("Outdated TLS version in use (TLS 1.2)")


async def tls_cert_expired(result: TlsResult) -> str | None:
    if not result.expired:
        return "Certificate is not expired"

    raise ValidationError("Certificate is expired")


async def tls_cert_self_signed(result: TlsResult) -> str | None:
    if not result.self_signed:
        return "Certificate is CA-signed"

    raise ValidationError("Certificate is self-signed")


async def tls_cert_mismatched(result: TlsResult) -> str | None:
    if not result.mismatched:
        return "Certificate hostname matches"

    raise ValidationError("Certificate hostname mismatch")


async def tls_cert_revoked(result: TlsResult) -> str | None:
    if not result.revoked:
        return "Certificate is not revoked"

    raise ValidationError("Certificate has been revoked")


async def tls_cert_untrusted(result: TlsResult) -> str | None:
    if not result.untrusted:
        return "Certificate is trusted"

    raise ValidationError("Certificate is not trusted")


async def tls_cipher_weak(result: TlsResult) -> str | None:
    if not result.cipher:
        return None

    cipher_upper = result.cipher.upper()
    if not any(part.upper() in cipher_upper for part in _WEAK_CIPHER_SUBSTRINGS):
        return "Cipher suite is strong"

    raise ValidationError(f"Weak cipher negotiated ({result.cipher})", metadata={"cipher": result.cipher})
