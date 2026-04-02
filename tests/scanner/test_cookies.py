import pytest
from unittest.mock import MagicMock
from scanner.modules.cookies import CookieScanner
from scanner.modules.base import Severity


def _mock_response(set_cookie_headers):
    """Create mock response with multiple Set-Cookie headers."""
    resp = MagicMock()
    all_headers = [("set-cookie", v) for v in set_cookie_headers]
    resp.headers.multi_items.return_value = all_headers
    return resp


class TestCookieScanner:
    def setup_method(self):
        self.scanner = CookieScanner()

    def test_cookie_missing_secure(self):
        resp = _mock_response(["session=abc123; HttpOnly; SameSite=Lax"])
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING and "Secure" in f.title]
        assert len(warnings) == 1

    def test_cookie_missing_httponly(self):
        resp = _mock_response(["session=abc123; Secure; SameSite=Lax"])
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING and "HttpOnly" in f.title]
        assert len(warnings) == 1

    def test_cookie_missing_samesite(self):
        resp = _mock_response(["session=abc123; Secure; HttpOnly"])
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING and "SameSite" in f.title]
        assert len(warnings) == 1

    def test_cookie_samesite_none_is_warning(self):
        resp = _mock_response(["session=abc123; Secure; HttpOnly; SameSite=None"])
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING and "SameSite" in f.title]
        assert len(warnings) == 1

    def test_secure_cookie_is_clean(self):
        resp = _mock_response(["session=abc123; Secure; HttpOnly; SameSite=Lax"])
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_samesite_strict_is_clean(self):
        resp = _mock_response(["session=abc123; Secure; HttpOnly; SameSite=Strict"])
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_multiple_cookies_grouped(self):
        resp = _mock_response([
            "session=abc; HttpOnly; SameSite=Lax",
            "prefs=dark; HttpOnly; SameSite=Lax",
            "token=xyz; HttpOnly; SameSite=Lax",
        ])
        findings = self.scanner.run("https://example.com", resp)
        secure_warnings = [f for f in findings if f.severity == Severity.WARNING and "Secure" in f.title]
        assert len(secure_warnings) == 1
        assert "3" in secure_warnings[0].title or "3" in secure_warnings[0].detail

    def test_detail_shows_cookie_names(self):
        resp = _mock_response([
            "session=abc; HttpOnly; SameSite=Lax",
            "prefs=dark; HttpOnly; SameSite=Lax",
        ])
        findings = self.scanner.run("https://example.com", resp)
        secure_warnings = [f for f in findings if "Secure" in f.title]
        assert "session" in secure_warnings[0].detail
        assert "prefs" in secure_warnings[0].detail

    def test_no_cookies_returns_empty(self):
        resp = _mock_response([])
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://example.com", None)
        assert findings == []

    def test_max_five_cookie_names_in_detail(self):
        cookies = [f"c{i}=v; HttpOnly; SameSite=Lax" for i in range(8)]
        resp = _mock_response(cookies)
        findings = self.scanner.run("https://example.com", resp)
        secure_warnings = [f for f in findings if "Secure" in f.title]
        assert len(secure_warnings) == 1
        assert "dalších" in secure_warnings[0].detail or "..." in secure_warnings[0].detail
