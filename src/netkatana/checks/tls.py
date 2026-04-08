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
    _DETAIL = "SSL 3.0, TLS 1.0, and TLS 1.1 contain known vulnerabilities (BEAST, POODLE) and are rejected by modern clients."

    async def check(self, result: TlsResult) -> list[Finding]:
        if result.tls_version not in _DEPRECATED_TLS_VERSIONS:
            return [
                Finding(
                    code="tls_version_deprecated",
                    severity=Severity.PASS,
                    title="TLS version is not deprecated",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code="tls_version_deprecated",
                severity=Severity.CRITICAL,
                title=f"Deprecated TLS version in use ({result.tls_version.upper()})",
                detail=self._DETAIL,
                metadata={"tls_version": result.tls_version},
            )
        ]


class TlsVersionOutdated(AbstractTlsCheck):
    _DETAIL = "TLS 1.3 offers improved security and performance over TLS 1.2."

    async def check(self, result: TlsResult) -> list[Finding]:
        if result.tls_version not in _OUTDATED_TLS_VERSIONS:
            return [
                Finding(
                    code="tls_version_outdated",
                    severity=Severity.PASS,
                    title="TLS version is current",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code="tls_version_outdated",
                severity=Severity.NOTICE,
                title="Outdated TLS version in use (TLS 1.2)",
                detail=self._DETAIL,
            )
        ]


class TlsCertExpired(AbstractTlsCheck):
    _DETAIL = "TLS certificates have an expiry date; after that date, clients will reject the connection or display a security warning."

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.expired:
            return [
                Finding(
                    code="tls_cert_expired",
                    severity=Severity.PASS,
                    title="Certificate is not expired",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code="tls_cert_expired",
                severity=Severity.CRITICAL,
                title="Certificate is expired",
                detail=self._DETAIL,
            )
        ]


class TlsCertSelfSigned(AbstractTlsCheck):
    _DETAIL = "TLS certificates must be issued by a CA trusted by the client; self-signed certificates are rejected or warned about by browsers."

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.self_signed:
            return [
                Finding(
                    code="tls_cert_self_signed",
                    severity=Severity.PASS,
                    title="Certificate is CA-signed",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code="tls_cert_self_signed",
                severity=Severity.CRITICAL,
                title="Certificate is self-signed",
                detail=self._DETAIL,
            )
        ]


class TlsCertMismatched(AbstractTlsCheck):
    _DETAIL = (
        "A TLS certificate must cover the hostname being accessed; a mismatch causes clients to reject the connection."
    )

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.mismatched:
            return [
                Finding(
                    code="tls_cert_mismatched",
                    severity=Severity.PASS,
                    title="Certificate hostname matches",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code="tls_cert_mismatched",
                severity=Severity.CRITICAL,
                title="Certificate hostname mismatch",
                detail=self._DETAIL,
            )
        ]


class TlsCertRevoked(AbstractTlsCheck):
    _DETAIL = "CAs can revoke certificates before they expire; clients that check revocation status will reject a revoked certificate."

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.revoked:
            return [
                Finding(
                    code="tls_cert_revoked",
                    severity=Severity.PASS,
                    title="Certificate is not revoked",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code="tls_cert_revoked",
                severity=Severity.CRITICAL,
                title="Certificate has been revoked",
                detail=self._DETAIL,
            )
        ]


class TlsCertUntrusted(AbstractTlsCheck):
    _DETAIL = "The TLS certificate chain must be traceable to a root CA trusted by the client; an unverifiable chain causes connection rejection."

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.untrusted:
            return [
                Finding(
                    code="tls_cert_untrusted",
                    severity=Severity.PASS,
                    title="Certificate is trusted",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code="tls_cert_untrusted",
                severity=Severity.CRITICAL,
                title="Certificate is not trusted",
                detail=self._DETAIL,
            )
        ]


class TlsCipherWeak(AbstractTlsCheck):
    _DETAIL = "Cipher suites such as RC4, NULL, EXPORT, DES, 3DES, IDEA, and SEED have known weaknesses and should not be negotiated."

    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.cipher:
            return []

        cipher_upper = result.cipher.upper()
        if not any(s.upper() in cipher_upper for s in _WEAK_CIPHER_SUBSTRINGS):
            return [
                Finding(
                    code="tls_cipher_weak",
                    severity=Severity.PASS,
                    title="Cipher suite is strong",
                    detail=self._DETAIL,
                )
            ]

        return [
            Finding(
                code="tls_cipher_weak",
                severity=Severity.WARNING,
                title=f"Weak cipher negotiated ({result.cipher})",
                detail=self._DETAIL,
                metadata={"cipher": result.cipher},
            )
        ]
