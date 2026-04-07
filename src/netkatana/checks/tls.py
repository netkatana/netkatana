from netkatana.models import AbstractTlsCheck, Finding, Severity, TlsResult

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
    async def check(self, result: TlsResult) -> list[Finding]:
        if result.tls_version not in _DEPRECATED_TLS_VERSIONS:
            return [
                Finding(
                    code="tls_version_deprecated",
                    severity=Severity.PASS,
                    title="TLS version is not deprecated",
                    detail=(
                        "Deprecated TLS versions (SSLv3, TLS 1.0, TLS 1.1) contain known vulnerabilities "
                        "(e.g. BEAST, POODLE). Upgrade to TLS 1.3 or at minimum TLS 1.2."
                    ),
                )
            ]

        return [
            Finding(
                code="tls_version_deprecated",
                severity=Severity.CRITICAL,
                title=f"Deprecated TLS version in use ({result.tls_version.upper()})",
                detail=(
                    f"{result.tls_version.upper()} is deprecated and contains known vulnerabilities "
                    "(e.g. BEAST, POODLE). Upgrade to TLS 1.3 or at minimum TLS 1.2."
                ),
            )
        ]


class TlsVersionOutdated(AbstractTlsCheck):
    async def check(self, result: TlsResult) -> list[Finding]:
        if result.tls_version not in _OUTDATED_TLS_VERSIONS:
            return [
                Finding(
                    code="tls_version_outdated",
                    severity=Severity.PASS,
                    title="TLS version is current",
                    detail="TLS 1.2 is functional but TLS 1.3 offers better security and performance. Consider upgrading.",
                )
            ]

        return [
            Finding(
                code="tls_version_outdated",
                severity=Severity.NOTICE,
                title="Outdated TLS version in use (TLS 1.2)",
                detail="TLS 1.2 is functional but TLS 1.3 offers better security and performance. Consider upgrading.",
            )
        ]


class TlsCertExpired(AbstractTlsCheck):
    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.expired:
            return [
                Finding(
                    code="tls_cert_expired",
                    severity=Severity.PASS,
                    title="Certificate is not expired",
                    detail="The TLS certificate has passed its expiry date. Clients will receive security warnings and may refuse to connect.",
                )
            ]

        return [
            Finding(
                code="tls_cert_expired",
                severity=Severity.CRITICAL,
                title="Certificate is expired",
                detail="The TLS certificate has passed its expiry date. Clients will receive security warnings and may refuse to connect.",
            )
        ]


class TlsCertSelfSigned(AbstractTlsCheck):
    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.self_signed:
            return [
                Finding(
                    code="tls_cert_self_signed",
                    severity=Severity.PASS,
                    title="Certificate is CA-signed",
                    detail="The certificate was not issued by a trusted CA. Browsers and clients will display security warnings or refuse the connection.",
                )
            ]

        return [
            Finding(
                code="tls_cert_self_signed",
                severity=Severity.CRITICAL,
                title="Certificate is self-signed",
                detail="The certificate was not issued by a trusted CA. Browsers and clients will display security warnings or refuse the connection.",
            )
        ]


class TlsCertMismatched(AbstractTlsCheck):
    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.mismatched:
            return [
                Finding(
                    code="tls_cert_mismatched",
                    severity=Severity.PASS,
                    title="Certificate hostname matches",
                    detail="The certificate does not cover the requested hostname. Clients will reject the connection.",
                )
            ]

        return [
            Finding(
                code="tls_cert_mismatched",
                severity=Severity.CRITICAL,
                title="Certificate hostname mismatch",
                detail="The certificate does not cover the requested hostname. Clients will reject the connection.",
            )
        ]


class TlsCertRevoked(AbstractTlsCheck):
    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.revoked:
            return [
                Finding(
                    code="tls_cert_revoked",
                    severity=Severity.PASS,
                    title="Certificate is not revoked",
                    detail="The certificate authority has revoked this certificate, often due to key compromise. Clients that check revocation will reject it.",
                )
            ]

        return [
            Finding(
                code="tls_cert_revoked",
                severity=Severity.CRITICAL,
                title="Certificate has been revoked",
                detail="The certificate authority has revoked this certificate, often due to key compromise. Clients that check revocation will reject it.",
            )
        ]


class TlsCertUntrusted(AbstractTlsCheck):
    async def check(self, result: TlsResult) -> list[Finding]:
        if not result.untrusted:
            return [
                Finding(
                    code="tls_cert_untrusted",
                    severity=Severity.PASS,
                    title="Certificate is trusted",
                    detail="The certificate chain cannot be verified against any trusted root CA. Clients will display security warnings or refuse to connect.",
                )
            ]

        return [
            Finding(
                code="tls_cert_untrusted",
                severity=Severity.CRITICAL,
                title="Certificate is not trusted",
                detail="The certificate chain cannot be verified against any trusted root CA. Clients will display security warnings or refuse to connect.",
            )
        ]


class TlsCipherWeak(AbstractTlsCheck):
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
                    detail=(
                        "Weak cipher suites can be vulnerable to decryption attacks. "
                        "Configure the server to prefer strong ciphers."
                    ),
                )
            ]

        return [
            Finding(
                code="tls_cipher_weak",
                severity=Severity.WARNING,
                title=f"Weak cipher negotiated ({result.cipher})",
                detail=(
                    f"The negotiated cipher suite '{result.cipher}' is considered weak. "
                    "Weak ciphers can be vulnerable to decryption attacks. Configure the server to prefer strong ciphers."
                ),
            )
        ]
