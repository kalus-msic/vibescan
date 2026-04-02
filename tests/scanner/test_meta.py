import pytest
from unittest.mock import MagicMock
from scanner.modules.meta import MetaTagScanner
from scanner.modules.base import Severity


def _mock_response(text):
    resp = MagicMock()
    resp.text = text
    return resp


class TestMetaTagScanner:
    def setup_method(self):
        self.scanner = MetaTagScanner()

    def test_detects_wordpress_with_version(self):
        resp = _mock_response('<meta name="generator" content="WordPress 6.4.2">')
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert "WordPress 6.4.2" in warnings[0].detail

    def test_detects_joomla_with_version(self):
        resp = _mock_response('<meta name="generator" content="Joomla! 4.3.2">')
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_detects_drupal_with_version(self):
        resp = _mock_response('<meta name="generator" content="Drupal 10.2.1">')
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_cms_without_version_is_info(self):
        resp = _mock_response('<meta name="generator" content="WordPress">')
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 1

    def test_unknown_generator_is_info(self):
        resp = _mock_response('<meta name="generator" content="MyCustomCMS">')
        findings = self.scanner.run("https://example.com", resp)
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 1

    def test_no_generator_returns_empty(self):
        resp = _mock_response('<html><head><meta charset="utf-8"></head><body></body></html>')
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://example.com", None)
        assert findings == []

    def test_detail_contains_full_content(self):
        resp = _mock_response('<meta name="generator" content="WordPress 6.4.2">')
        findings = self.scanner.run("https://example.com", resp)
        assert findings[0].detail == "WordPress 6.4.2"

    def test_generator_case_insensitive(self):
        resp = _mock_response('<meta NAME="Generator" content="WordPress 6.4.2">')
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 1
