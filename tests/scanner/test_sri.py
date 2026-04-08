import pytest
from unittest.mock import MagicMock
from scanner.modules.sri import SRIScanner
from scanner.modules.base import Severity


def _mock_response(text, headers=None):
    resp = MagicMock()
    resp.text = text
    resp.headers = headers or {}
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
        problems = [f for f in findings if f.severity not in (Severity.OK,)]
        assert len(problems) == 0
        ok = [f for f in findings if f.severity == Severity.OK]
        assert len(ok) == 1
        assert ok[0].id == "sri-ok"

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

    def test_multiple_external_scripts_grouped(self):
        resp = _mock_response(
            '<script src="https://cdn1.com/a.js"></script>'
            '<script src="https://cdn2.com/b.js"></script>'
            '<script src="https://cdn3.com/c.js" integrity="sha384-ok"></script>'
        )
        findings = self.scanner.run("https://mysite.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert "(2×)" in warnings[0].title
        assert "cdn1.com" in warnings[0].detail
        assert "cdn2.com" in warnings[0].detail

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

    def test_no_csp_missing_sri_is_warning(self):
        """No CSP + no SRI → WARNING (no protection at all)."""
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js"></script>',
            headers={},
        )
        findings = self.scanner.run("https://mysite.com", resp)
        script_findings = [f for f in findings if f.id == "missing-sri-script"]
        assert len(script_findings) == 1
        assert script_findings[0].severity == Severity.WARNING
        assert "nemá silné CSP" in script_findings[0].description

    def test_strong_csp_nonce_missing_sri_is_info(self):
        """CSP with nonce + no SRI → INFO (CSP is primary, SRI is bonus)."""
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js"></script>',
            headers={"content-security-policy": "script-src 'nonce-abc123' 'strict-dynamic'"},
        )
        findings = self.scanner.run("https://mysite.com", resp)
        script_findings = [f for f in findings if f.id == "missing-sri-script"]
        assert len(script_findings) == 1
        assert script_findings[0].severity == Severity.INFO
        assert "CSP s nonce" in script_findings[0].description

    def test_strict_dynamic_csp_missing_sri_is_info(self):
        """CSP with strict-dynamic + no SRI → INFO."""
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js"></script>',
            headers={"content-security-policy": "script-src 'strict-dynamic' https:"},
        )
        findings = self.scanner.run("https://mysite.com", resp)
        script_findings = [f for f in findings if f.id == "missing-sri-script"]
        assert len(script_findings) == 1
        assert script_findings[0].severity == Severity.INFO

    def test_weak_csp_without_nonce_missing_sri_is_warning(self):
        """CSP without nonce/strict-dynamic + no SRI → still WARNING."""
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js"></script>',
            headers={"content-security-policy": "script-src 'self' https://cdn.example.com"},
        )
        findings = self.scanner.run("https://mysite.com", resp)
        script_findings = [f for f in findings if f.id == "missing-sri-script"]
        assert len(script_findings) == 1
        assert script_findings[0].severity == Severity.WARNING

    def test_csp_report_only_with_nonce_counts(self):
        """CSP-Report-Only with nonce also counts as strong CSP."""
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js"></script>',
            headers={"content-security-policy-report-only": "script-src 'nonce-xyz'"},
        )
        findings = self.scanner.run("https://mysite.com", resp)
        script_findings = [f for f in findings if f.id == "missing-sri-script"]
        assert len(script_findings) == 1
        assert script_findings[0].severity == Severity.INFO

    def test_csp_nonce_plus_sri_is_best(self):
        """CSP with nonce + SRI on all scripts → OK with dual-protection message."""
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js" integrity="sha384-abc"></script>',
            headers={"content-security-policy": "script-src 'nonce-abc123' 'strict-dynamic'"},
        )
        findings = self.scanner.run("https://mysite.com", resp)
        ok = [f for f in findings if f.id == "sri-csp-ok"]
        assert len(ok) == 1
        assert ok[0].severity == Severity.OK
        assert "dvouvrstvá" in ok[0].description
