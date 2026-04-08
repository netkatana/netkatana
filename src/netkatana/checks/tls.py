from typing import ClassVar

from netkatana.checks.config import get_detail, get_severity
from netkatana.types import AbstractTlsCheck, Finding, Severity, TlsResult

_DEPRECATED_TLS_VERSIONS = {"ssl30", "tls10", "tls11"}
_OUTDATED_TLS_VERSIONS = {"tls12"}

# Cipher suites considered weak when negotiated
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


class TlsVersionDeprecated(AbstractTlsCheck):
    _CODE: ClassVar[str] = "tls_version_deprecated"

    async def check(self, result: TlsResult) -> list[Finding]:
        if result.tls_version not in _DEPRECATED_TLS_VERSIONS:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="TLS version is not deprecated",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title=f"Deprecated TLS version in use ({result.tls_version.upper()})",
                detail=get_detail(self._CODE),
                metadata={"tls_version": result.tls_version},
            )
        ]


class TlsVersionOutdated(AbstractTlsCheck):
    _CODE: ClassVar[str] = "tls_version_outdated"

    async def check(self, result: TlsResult) -> list[Finding]:
        if result.tls_version not in _OUTDATED_TLS_VERSIONS:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="TLS version is current",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Outdated TLS version in use (TLS 1.2)",
                detail=get_detail(self._CODE),
            )
        ]


class TlsCertExpired(AbstractTlsCheck):
    _CODE: ClassVar[str] = "tls_cert_expired"

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.expired:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Certificate is not expired",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Certificate is expired",
                detail=get_detail(self._CODE),
            )
        ]


class TlsCertSelfSigned(AbstractTlsCheck):
    _CODE: ClassVar[str] = "tls_cert_self_signed"

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.self_signed:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Certificate is CA-signed",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Certificate is self-signed",
                detail=get_detail(self._CODE),
            )
        ]


class TlsCertMismatched(AbstractTlsCheck):
    _CODE: ClassVar[str] = "tls_cert_mismatched"

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.mismatched:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Certificate hostname matches",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Certificate hostname mismatch",
                detail=get_detail(self._CODE),
            )
        ]


class TlsCertRevoked(AbstractTlsCheck):
    _CODE: ClassVar[str] = "tls_cert_revoked"

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.revoked:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Certificate is not revoked",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Certificate has been revoked",
                detail=get_detail(self._CODE),
            )
        ]


class TlsCertUntrusted(AbstractTlsCheck):
    _CODE: ClassVar[str] = "tls_cert_untrusted"

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.untrusted:
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Certificate is trusted",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title="Certificate is not trusted",
                detail=get_detail(self._CODE),
            )
        ]


class TlsCipherWeak(AbstractTlsCheck):
    _CODE: ClassVar[str] = "tls_cipher_weak"

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.cipher:
            return []

        cipher_upper = result.cipher.upper()
        if not any(s.upper() in cipher_upper for s in _WEAK_CIPHER_SUBSTRINGS):
            return [
                Finding(
                    code=self._CODE,
                    severity=Severity.PASS,
                    title="Cipher suite is strong",
                    detail=get_detail(self._CODE),
                )
            ]

        return [
            Finding(
                code=self._CODE,
                severity=get_severity(self._CODE),
                title=f"Weak cipher negotiated ({result.cipher})",
                detail=get_detail(self._CODE),
                metadata={"cipher": result.cipher},
            )
        ]
