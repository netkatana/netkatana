import pytest

from netkatana.types import StrictTransportSecurityHeader
from netkatana.utils import extract_host, parse_strict_transport_security_header


def test_extract_host_bare_hostname():
    assert extract_host("example.com") == "example.com"


def test_extract_host_http_scheme():
    assert extract_host("http://example.com") == "example.com"


def test_extract_host_https_scheme():
    assert extract_host("https://example.com") == "example.com"


def test_extract_host_strips_path():
    assert extract_host("https://example.com/some/path?q=1") == "example.com"


def test_extract_host_preserves_port():
    assert extract_host("http://example.com:8080") == "example.com:8080"


def test_parse_strict_transport_security_header_max_age_only():
    result = parse_strict_transport_security_header("max-age=31536000")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=False, preload=False)


def test_parse_strict_transport_security_header_with_include_subdomains():
    result = parse_strict_transport_security_header("max-age=31536000; includeSubDomains")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=True, preload=False)


def test_parse_strict_transport_security_header_with_include_subdomains_and_preload():
    result = parse_strict_transport_security_header("max-age=31536000; includeSubDomains; preload")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=True, preload=True)


def test_parse_strict_transport_security_header_max_age_zero():
    result = parse_strict_transport_security_header("max-age=0")
    assert result == StrictTransportSecurityHeader(max_age=0, include_subdomains=False, preload=False)


def test_parse_strict_transport_security_header_case_insensitive_directives():
    result = parse_strict_transport_security_header("max-age=31536000; includesubdomains; PRELOAD")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=True, preload=True)


def test_parse_strict_transport_security_header_invalid_non_numeric_max_age():
    with pytest.raises(ValueError):
        parse_strict_transport_security_header("max-age=abc")


def test_parse_strict_transport_security_header_invalid_missing_max_age():
    with pytest.raises(ValueError):
        parse_strict_transport_security_header("includeSubDomains")


def test_parse_strict_transport_security_header_any_directive_order():
    result = parse_strict_transport_security_header("includeSubDomains; preload; max-age=31536000")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=True, preload=True)


def test_parse_strict_transport_security_header_no_space_after_semicolon():
    result = parse_strict_transport_security_header("max-age=31536000;includeSubDomains;preload")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=True, preload=True)


def test_parse_strict_transport_security_header_unknown_directives_ignored():
    result = parse_strict_transport_security_header("max-age=31536000; unknownDirective; anotherUnknown=value")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=False, preload=False)


def test_parse_strict_transport_security_header_trailing_semicolon():
    result = parse_strict_transport_security_header("max-age=31536000; includeSubDomains;")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=True, preload=False)


def test_parse_strict_transport_security_header_double_semicolon():
    result = parse_strict_transport_security_header("max-age=31536000;; includeSubDomains")
    assert result == StrictTransportSecurityHeader(max_age=31536000, include_subdomains=True, preload=False)


def test_parse_strict_transport_security_header_invalid_whitespace_around_equals():
    with pytest.raises(ValueError):
        parse_strict_transport_security_header("max-age = 31536000")


def test_parse_strict_transport_security_header_invalid_empty_string():
    with pytest.raises(ValueError):
        parse_strict_transport_security_header("")


def test_parse_strict_transport_security_header_invalid_garbage():
    with pytest.raises(ValueError):
        parse_strict_transport_security_header("garbage")
