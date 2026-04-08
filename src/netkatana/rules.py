from netkatana.types import HttpRule, Severity
from netkatana.validators.http.headers import strict_transport_security_missing

http_rules = [
    HttpRule(
        code="headers_hsts_missing",
        severity=Severity.CRITICAL,
        detail="The 'Strict-Transport-Security' header instructs browsers to always use HTTPS for this domain, preventing protocol downgrade and SSL stripping attacks.",
        validator=strict_transport_security_missing,
    )
]
