from unittest.mock import MagicMock, patch
from scanner.modules.ssl_check import SSLScanner
from scanner.modules.base import Severity


def make_response(url="https://example.com", history=None):
    resp = MagicMock()
    resp.url = url
    resp.history = history or []
    resp.headers = {}
    return resp


def test_https_redirect_ok():
    http_resp = MagicMock()
    http_resp.url = "http://example.com"

    final_resp = MagicMock()
    final_resp.url = "https://example.com"
    final_resp.history = [http_resp]
    final_resp.headers = {}

    scanner = SSLScanner()
    findings = scanner.run("http://example.com", final_resp)
    ids = [f.id for f in findings]
    assert "https-redirect-ok" in ids


def test_no_https_redirect_is_critical():
    resp = MagicMock()
    resp.url = "http://example.com"
    resp.history = []
    resp.headers = {}

    scanner = SSLScanner()
    findings = scanner.run("http://example.com", resp)
    ids = [f.id for f in findings]
    assert "missing-https-redirect" in ids
    f = next(x for x in findings if x.id == "missing-https-redirect")
    assert f.severity == Severity.CRITICAL
