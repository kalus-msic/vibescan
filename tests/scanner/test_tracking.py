import pytest
from unittest.mock import MagicMock
from scanner.modules.tracking import TrackingConsentScanner
from scanner.modules.base import Severity


def _mock_response(text):
    resp = MagicMock()
    resp.text = text
    return resp


class TestTrackingConsentScanner:
    def setup_method(self):
        self.scanner = TrackingConsentScanner()

    def test_detects_gtm_in_html(self):
        resp = _mock_response(
            '<script src="https://www.googletagmanager.com/gtag/js?id=G-XXXXX"></script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert "Google Tag Manager" in warnings[0].detail

    def test_detects_google_analytics(self):
        resp = _mock_response(
            '<script src="https://www.google-analytics.com/analytics.js"></script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_detects_facebook_pixel(self):
        resp = _mock_response(
            '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_detects_hotjar(self):
        resp = _mock_response(
            '<script src="https://static.hotjar.com/c/hotjar-123.js"></script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_multiple_trackers_grouped_in_one_finding(self):
        resp = _mock_response(
            '<script src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>'
            '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>'
            '<script src="https://static.hotjar.com/c/hotjar-1.js"></script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert "(3×)" in warnings[0].title
        assert "Google Tag Manager" in warnings[0].detail
        assert "Facebook Pixel" in warnings[0].detail
        assert "Hotjar" in warnings[0].detail

    def test_deduplicates_same_host(self):
        resp = _mock_response(
            '<script src="https://www.googletagmanager.com/gtag/js?id=G-A"></script>'
            '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-B"></script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_no_tracking_returns_empty(self):
        resp = _mock_response(
            '<html><body><script src="https://cdn.example.com/app.js"></script></body></html>'
        )
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://example.com", None)
        assert findings == []

    def test_no_scripts_returns_empty(self):
        resp = _mock_response('<html><body><p>Hello</p></body></html>')
        findings = self.scanner.run("https://example.com", resp)
        assert len(findings) == 0

    def test_detects_linkedin_insight(self):
        resp = _mock_response(
            '<script src="https://snap.licdn.com/li.lms-analytics/insight.min.js"></script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_detects_tiktok_pixel(self):
        resp = _mock_response(
            '<script src="https://analytics.tiktok.com/i18n/pixel/events.js"></script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
