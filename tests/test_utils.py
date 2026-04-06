from netkatana.utils import extract_host


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
