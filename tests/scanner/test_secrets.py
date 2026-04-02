import pytest
from unittest.mock import MagicMock
from scanner.modules.secrets import SecretLeakageScanner
from scanner.modules.base import Severity


def _mock_response(text):
    resp = MagicMock()
    resp.text = text
    return resp


class TestSecretLeakageScanner:
    def setup_method(self):
        self.scanner = SecretLeakageScanner()

    def test_detects_openai_key(self):
        resp = _mock_response('<script>const key = "sk-proj-abc12345def789ghi012jkl";</script>')
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "OpenAI" in critical[0].title
        assert "sk-proj-abc12345..." in critical[0].detail

    def test_detects_aws_key(self):
        resp = _mock_response('<div data-key="AKIAIOSFODNN7EXAMPLE"></div>')
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "AWS" in critical[0].title

    def test_detects_github_pat(self):
        resp = _mock_response('var token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";')
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "GitHub" in critical[0].title

    def test_detects_stripe_secret(self):
        resp = _mock_response('const stripe = "sk_live_abc123def456ghi789jkl012mno";')
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "Stripe" in critical[0].title

    def test_detects_supabase_secret(self):
        resp = _mock_response('const key = "sb_secret_abcdefghijklmnopqrstuvwxyz123456";')
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "Supabase" in critical[0].title

    def test_detects_supabase_pat(self):
        resp = _mock_response('token: "sbp_1234567890abcdef1234567890abcdef12345678"')
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "Supabase" in critical[0].title

    def test_detects_firebase_key(self):
        resp = _mock_response('apiKey: "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"')
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "Firebase" in critical[0].title

    def test_detects_vercel_pat(self):
        resp = _mock_response('const token = "vcp_abcdefghijklmnopqrstuvwx";')
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "Vercel" in critical[0].title

    def test_detects_legacy_supabase_jwt(self):
        resp = _mock_response(
            'const key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9.abc123def456";'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) >= 1
        assert any("JWT" in f.title for f in warnings)

    def test_detects_generic_secret(self):
        resp = _mock_response('const config = { password: "super_secret_123" };')
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) >= 1

    def test_no_findings_on_clean_html(self):
        resp = _mock_response('<html><body><h1>Hello World</h1></body></html>')
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://example.com", None)
        assert findings == []

    def test_masks_key_in_detail(self):
        resp = _mock_response('<script>key = "sk-proj-abc12345def789ghi012jkl";</script>')
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 1
        assert findings[0].detail.endswith("...")
        assert len(findings[0].detail) < 30

    def test_multiple_keys_produce_multiple_findings(self):
        resp = _mock_response(
            'key1 = "sk-proj-abc12345def789ghi012jkl"; '
            'key2 = "AKIAIOSFODNN7EXAMPLE";'
        )
        findings = self.scanner.run("https://example.com", resp)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 2
