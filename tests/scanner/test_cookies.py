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

    def test_session_cookie_missing_secure_is_critical(self):
        """Session/auth cookie bez Secure → CRITICAL (převzetí účtu)."""
        resp = _mock_response(["session=abc123; HttpOnly; SameSite=Lax"])
        findings = self.scanner.run("https://example.com", resp)
        secure = [f for f in findings if "Secure" in f.title]
        assert len(secure) == 1
        assert secure[0].severity == Severity.CRITICAL

    def test_session_cookie_missing_httponly_is_critical(self):
        resp = _mock_response(["session=abc123; Secure; SameSite=Lax"])
        findings = self.scanner.run("https://example.com", resp)
        ho = [f for f in findings if "HttpOnly" in f.title]
        assert len(ho) == 1
        assert ho[0].severity == Severity.CRITICAL

    def test_session_cookie_missing_samesite_is_critical(self):
        resp = _mock_response(["session=abc123; Secure; HttpOnly"])
        findings = self.scanner.run("https://example.com", resp)
        ss = [f for f in findings if "SameSite" in f.title]
        assert len(ss) == 1
        assert ss[0].severity == Severity.CRITICAL

    def test_session_cookie_samesite_none_is_critical(self):
        resp = _mock_response(["session=abc123; Secure; HttpOnly; SameSite=None"])
        findings = self.scanner.run("https://example.com", resp)
        ss = [f for f in findings if "SameSite" in f.title]
        assert len(ss) == 1
        assert ss[0].severity == Severity.CRITICAL

    def test_one_nonsession_cookie_is_info(self):
        """1 prefs cookie bez flagu → INFO (low impact)."""
        resp = _mock_response(["prefs=dark"])
        findings = self.scanner.run("https://example.com", resp)
        for f in findings:
            assert f.severity == Severity.INFO

    def test_three_nonsession_cookies_is_warning(self):
        """3+ non-session cookies bez flagu → WARNING."""
        resp = _mock_response([
            "prefs=a; HttpOnly; SameSite=Lax",  # missing Secure only
            "lang=cs; HttpOnly; SameSite=Lax",
            "theme=dark; HttpOnly; SameSite=Lax",
        ])
        findings = self.scanner.run("https://example.com", resp)
        secure = [f for f in findings if "Secure" in f.title]
        assert len(secure) == 1
        assert secure[0].severity == Severity.WARNING

    def test_session_promotes_severity_in_mixed_set(self):
        """1 session + 5 prefs → CRITICAL (session přebije warning threshold)."""
        resp = _mock_response([
            "session=abc; HttpOnly; SameSite=Lax",
            "a=1; HttpOnly; SameSite=Lax",
            "b=2; HttpOnly; SameSite=Lax",
            "c=3; HttpOnly; SameSite=Lax",
            "d=4; HttpOnly; SameSite=Lax",
            "e=5; HttpOnly; SameSite=Lax",
        ])
        findings = self.scanner.run("https://example.com", resp)
        secure = [f for f in findings if "Secure" in f.title]
        assert secure[0].severity == Severity.CRITICAL

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
        secure = [f for f in findings if "Secure" in f.title]
        assert len(secure) == 1
        assert "3" in secure[0].title or "3" in secure[0].detail

    def test_detail_shows_cookie_names(self):
        resp = _mock_response([
            "session=abc; HttpOnly; SameSite=Lax",
            "prefs=dark; HttpOnly; SameSite=Lax",
        ])
        findings = self.scanner.run("https://example.com", resp)
        secure = [f for f in findings if "Secure" in f.title]
        assert "session" in secure[0].detail
        assert "prefs" in secure[0].detail

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
        secure = [f for f in findings if "Secure" in f.title]
        assert len(secure) == 1
        assert "dalších" in secure[0].detail or "..." in secure[0].detail
