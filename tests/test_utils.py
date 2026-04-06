from netkatana.utils import parse_host


def test_parse_host_bare_hostname():
    assert parse_host("example.com") == "example.com"


def test_parse_host_http_scheme():
    assert parse_host("http://example.com") == "example.com"


def test_parse_host_https_scheme():
    assert parse_host("https://example.com") == "example.com"


def test_parse_host_strips_path():
    assert parse_host("https://example.com/some/path?q=1") == "example.com"


def test_parse_host_preserves_port():
    assert parse_host("http://example.com:8080") == "example.com:8080"
