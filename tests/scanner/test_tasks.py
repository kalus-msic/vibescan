from unittest.mock import patch, MagicMock
import pytest
from django.test import TestCase
from scanner.models import ScanResult, ScanStatus
from scanner.tasks import run_scan


def _make_mock_response(url="https://example.com", content_type="text/html", body=b"<html><body>Test</body></html>"):
    """Create a mock response compatible with _fetch_url's stream-based approach."""
    resp = MagicMock()
    resp.headers = {"content-type": content_type}
    resp.url = url
    resp.history = []
    resp.text = body.decode("utf-8", errors="ignore")
    resp._content = body
    return resp


class TestRunScanTask(TestCase):

    @patch("scanner.tasks._fetch_url")
    def test_successful_scan_sets_done_status(self, mock_fetch):
        mock_fetch.return_value = _make_mock_response()

        scan = ScanResult.objects.create(url="https://example.com")
        run_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == ScanStatus.DONE
        assert scan.vibe_score is not None
        assert isinstance(scan.findings, list)

    @patch("scanner.tasks._fetch_url")
    def test_failed_request_sets_failed_status(self, mock_fetch):
        import httpx
        mock_fetch.side_effect = httpx.RequestError("connection refused")

        scan = ScanResult.objects.create(url="https://example.com")
        run_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == ScanStatus.FAILED
        assert scan.error_message != ""

    @patch("scanner.tasks._fetch_url")
    def test_non_html_skips_html_scanner(self, mock_fetch):
        mock_fetch.return_value = _make_mock_response(
            content_type="application/json",
            body=b'{"key": "value"}',
        )

        scan = ScanResult.objects.create(url="https://api.example.com")
        run_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == ScanStatus.DONE
        # Should not have any HTML-related findings
        html_findings = [f for f in scan.findings if f.get("category") == "html"]
        assert len(html_findings) == 0

    @patch("scanner.tasks._fetch_url")
    def test_ssrf_redirect_blocked(self, mock_fetch):
        from scanner.validator import SSRFError
        mock_fetch.side_effect = SSRFError("Redirect na privátní IP adresu zablokován: 127.0.0.1")

        scan = ScanResult.objects.create(url="https://evil.com")
        run_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == ScanStatus.FAILED
        assert "privátní IP" in scan.error_message

    @patch("scanner.tasks._fetch_url")
    def test_oversized_response_blocked(self, mock_fetch):
        mock_fetch.side_effect = ValueError("Odpověď je příliš velká (> 5 MB)")

        scan = ScanResult.objects.create(url="https://example.com/huge.bin")
        run_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == ScanStatus.FAILED
        assert "příliš velká" in scan.error_message
