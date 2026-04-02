import pytest
from unittest.mock import MagicMock
from scanner.modules.sri import SRIScanner
from scanner.modules.base import Severity


def _mock_response(text):
    resp = MagicMock()
    resp.text = text
    return resp


class TestSRIScanner:
    def setup_method(self):
        self.scanner = SRIScanner()

    def test_detects_external_script_without_integrity(self):
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert "cdn.example.com/lib.js" in warnings[0].detail

    def test_no_warning_with_integrity(self):
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_ignores_same_origin_script(self):
        resp = _mock_response(
            '<script src="https://mysite.com/app.js"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_ignores_relative_script(self):
        resp = _mock_response('<script src="/static/app.js"></script>')
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_detects_external_stylesheet_without_integrity(self):
        resp = _mock_response(
            '<link rel="stylesheet" href="https://cdn.example.com/styles.css">'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 1

    def test_no_warning_stylesheet_with_integrity(self):
        resp = _mock_response(
            '<link rel="stylesheet" href="https://cdn.example.com/style.css" '
            'integrity="sha384-xyz789">'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_ignores_non_stylesheet_link(self):
        resp = _mock_response(
            '<link rel="icon" href="https://cdn.example.com/favicon.ico">'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_multiple_external_scripts(self):
        resp = _mock_response(
            '<script src="https://cdn1.com/a.js"></script>'
            '<script src="https://cdn2.com/b.js"></script>'
            '<script src="https://cdn3.com/c.js" integrity="sha384-ok"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 2

    def test_no_scripts_returns_empty(self):
        resp = _mock_response('<html><body><p>No scripts</p></body></html>')
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://mysite.com", None)
        assert findings == []

    def test_inline_script_ignored(self):
        resp = _mock_response('<script>console.log("hello")</script>')
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_skips_google_tag_manager(self):
        resp = _mock_response(
            '<script src="https://www.googletagmanager.com/gtag/js?id=G-XXXXX"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_skips_google_analytics(self):
        resp = _mock_response(
            '<script src="https://www.google-analytics.com/analytics.js"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_skips_facebook_sdk(self):
        resp = _mock_response(
            '<script src="https://connect.facebook.net/en_US/sdk.js"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_skips_google_fonts_stylesheet(self):
        resp = _mock_response(
            '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0

    def test_skips_stripe_js(self):
        resp = _mock_response(
            '<script src="https://js.stripe.com/v3/"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        assert len(findings) == 0
