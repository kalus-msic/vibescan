from unittest.mock import MagicMock
from scanner.modules.headers import HeaderScanner
from scanner.modules.base import Severity


def make_response(headers: dict):
    resp = MagicMock()
    resp.headers = headers
    return resp


def test_missing_csp_is_critical():
    scanner = HeaderScanner()
    findings = scanner.run("https://example.com", make_response({}))
    ids = [f.id for f in findings]
    assert "missing-csp" in ids
    csp_finding = next(f for f in findings if f.id == "missing-csp")
    assert csp_finding.severity == Severity.CRITICAL


def test_missing_hsts_is_critical():
    scanner = HeaderScanner()
    findings = scanner.run("https://example.com", make_response({}))
    ids = [f.id for f in findings]
    assert "missing-hsts" in ids


def test_present_headers_return_ok():
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    scanner = HeaderScanner()
    findings = scanner.run("https://example.com", make_response(headers))
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0


def test_server_header_leakage_is_warning():
    scanner = HeaderScanner()
    findings = scanner.run(
        "https://example.com",
        make_response({"server": "nginx/1.24.0"})
    )
    ids = [f.id for f in findings]
    assert "server-leakage" in ids
    finding = next(f for f in findings if f.id == "server-leakage")
    assert finding.severity == Severity.WARNING
