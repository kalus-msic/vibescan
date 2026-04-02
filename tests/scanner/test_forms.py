import pytest
from unittest.mock import MagicMock
from scanner.modules.forms import FormScanner
from scanner.modules.base import Severity


def _mock_response(text):
    resp = MagicMock()
    resp.text = text
    return resp


class TestFormScanner:
    def setup_method(self):
        self.scanner = FormScanner()

    def test_detects_post_form_without_csrf(self):
        resp = _mock_response(
            '<form method="POST" action="/login"><input type="text" name="user"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert "CSRF" in warnings[0].title

    def test_no_warning_with_django_csrf(self):
        resp = _mock_response(
            '<form method="POST"><input type="hidden" name="csrfmiddlewaretoken" value="abc123"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0

    def test_no_warning_with_wordpress_nonce(self):
        resp = _mock_response(
            '<form method="POST"><input type="hidden" name="_wpnonce" value="abc123"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0

    def test_no_warning_with_rails_token(self):
        resp = _mock_response(
            '<form method="POST"><input type="hidden" name="authenticity_token" value="abc123"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0

    def test_no_warning_with_generic_csrf(self):
        resp = _mock_response(
            '<form method="POST"><input type="hidden" name="_csrf_token" value="abc123"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0

    def test_ignores_get_forms(self):
        resp = _mock_response(
            '<form method="GET" action="/search"><input type="text" name="q"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0

    def test_post_form_case_insensitive(self):
        resp = _mock_response(
            '<form METHOD="post" action="/submit"><input type="text" name="data"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_detects_password_without_autocomplete(self):
        resp = _mock_response(
            '<form method="POST"><input type="hidden" name="csrf" value="x">'
            '<input type="password" name="pw"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 1
        assert "autocomplete" in info[0].title.lower()

    def test_password_autocomplete_on_triggers_info(self):
        resp = _mock_response(
            '<form method="POST"><input type="hidden" name="csrf" value="x">'
            '<input type="password" name="pw" autocomplete="on"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 1

    def test_password_autocomplete_off_is_clean(self):
        resp = _mock_response(
            '<form method="POST"><input type="hidden" name="csrf" value="x">'
            '<input type="password" name="pw" autocomplete="off"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 0

    def test_no_forms_returns_empty(self):
        resp = _mock_response('<html><body><p>No forms here</p></body></html>')
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://example.com", None)
        assert findings == []

    def test_detail_shows_form_action(self):
        resp = _mock_response(
            '<form method="POST" action="/api/login"><input type="text" name="user"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        assert findings[0].detail == "/api/login"

    def test_detail_shows_fallback_when_no_action(self):
        resp = _mock_response(
            '<form method="POST"><input type="text" name="user"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        assert findings[0].detail is not None
