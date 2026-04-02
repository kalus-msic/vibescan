import pytest
from scanner.validator import validate_scan_url, SSRFError


def test_valid_url_passes():
    assert validate_scan_url("https://example.com") == "https://example.com"


def test_http_url_passes():
    result = validate_scan_url("http://example.com")
    assert result == "http://example.com"


def test_private_ip_blocked():
    with pytest.raises(SSRFError):
        validate_scan_url("http://192.168.1.1")


def test_localhost_blocked():
    with pytest.raises(SSRFError):
        validate_scan_url("http://localhost/admin")


def test_loopback_blocked():
    with pytest.raises(SSRFError):
        validate_scan_url("http://127.0.0.1")


def test_10_range_blocked():
    with pytest.raises(SSRFError):
        validate_scan_url("http://10.0.0.1")


def test_172_16_range_blocked():
    with pytest.raises(SSRFError):
        validate_scan_url("http://172.16.0.1")


def test_missing_scheme_adds_https():
    assert validate_scan_url("example.com") == "https://example.com"


def test_missing_scheme_with_path():
    assert validate_scan_url("example.com/page") == "https://example.com/page"


def test_empty_url_raises():
    with pytest.raises(ValueError):
        validate_scan_url("")
