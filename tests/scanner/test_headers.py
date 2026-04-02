import pytest
from unittest.mock import MagicMock
from scanner.modules.headers import HeaderScanner
from scanner.modules.base import Severity


def _mock_response(headers):
    resp = MagicMock()
    resp.headers = headers
    return resp


class TestHeaderScannerXXSSProtection:
    def setup_method(self):
        self.scanner = HeaderScanner()

    def _base_headers(self, extra=None):
        """Minimal headers to avoid unrelated findings."""
        h = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        }
        if extra:
            h.update(extra)
        return h

    def test_xxss_protection_1_is_info(self):
        resp = _mock_response(self._base_headers({"X-XSS-Protection": "1"}))
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO and "XSS-Protection" in f.title]
        assert len(info) == 1

    def test_xxss_protection_1_mode_block_is_info(self):
        resp = _mock_response(self._base_headers({"X-XSS-Protection": "1; mode=block"}))
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO and "XSS-Protection" in f.title]
        assert len(info) == 1

    def test_xxss_protection_0_is_silent(self):
        resp = _mock_response(self._base_headers({"X-XSS-Protection": "0"}))
        findings = self.scanner.run("https://example.com", resp)
        xss_findings = [f for f in findings if "XSS-Protection" in f.title]
        assert len(xss_findings) == 0

    def test_xxss_protection_absent_is_silent(self):
        resp = _mock_response(self._base_headers())
        findings = self.scanner.run("https://example.com", resp)
        xss_findings = [f for f in findings if "XSS-Protection" in f.title]
        assert len(xss_findings) == 0


class TestHeaderScannerCOOP:
    def setup_method(self):
        self.scanner = HeaderScanner()

    def _base_headers(self, extra=None):
        h = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        }
        if extra:
            h.update(extra)
        return h

    def test_missing_coop_is_info(self):
        resp = _mock_response(self._base_headers())
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO and "Cross-Origin-Opener" in f.title]
        assert len(info) == 1

    def test_coop_present_is_silent(self):
        resp = _mock_response(self._base_headers({"Cross-Origin-Opener-Policy": "same-origin"}))
        findings = self.scanner.run("https://example.com", resp)
        coop_findings = [f for f in findings if "Cross-Origin-Opener" in f.title]
        assert len(coop_findings) == 0
