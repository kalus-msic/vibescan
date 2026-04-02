import pytest
from unittest.mock import MagicMock
from scanner.modules.cors import CORSScanner
from scanner.modules.base import Severity


def _mock_response(headers):
    resp = MagicMock()
    resp.headers = headers
    return resp


class TestCORSScanner:
    def setup_method(self):
        self.scanner = CORSScanner()

    def test_wildcard_with_credentials_is_critical(self):
        resp = _mock_response({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "credentials" in critical[0].title.lower() or "credentials" in critical[0].description.lower()

    def test_wildcard_without_credentials_is_warning(self):
        resp = _mock_response({
            "Access-Control-Allow-Origin": "*",
        })
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_specific_origin_without_vary_is_info(self):
        resp = _mock_response({
            "Access-Control-Allow-Origin": "https://app.example.com",
        })
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 1
        assert "Vary" in info[0].title or "Vary" in info[0].description

    def test_specific_origin_with_vary_is_clean(self):
        resp = _mock_response({
            "Access-Control-Allow-Origin": "https://app.example.com",
            "Vary": "Origin",
        })
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_vary_with_multiple_values_containing_origin(self):
        resp = _mock_response({
            "Access-Control-Allow-Origin": "https://app.example.com",
            "Vary": "Accept-Encoding, Origin",
        })
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_no_cors_headers_is_silent(self):
        resp = _mock_response({"Content-Type": "text/html"})
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://example.com", None)
        assert findings == []
