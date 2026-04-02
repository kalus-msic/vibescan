from unittest.mock import patch, MagicMock
import pytest
from django.test import TestCase
from scanner.models import ScanResult, ScanStatus
from scanner.tasks import run_scan


class TestRunScanTask(TestCase):

    @patch("scanner.tasks.httpx.get")
    def test_successful_scan_sets_done_status(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {"content-type": "text/html"}
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_get.return_value = mock_response

        scan = ScanResult.objects.create(url="https://example.com")
        run_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == ScanStatus.DONE
        assert scan.vibe_score is not None
        assert isinstance(scan.findings, list)

    @patch("scanner.tasks.httpx.get")
    def test_failed_request_sets_failed_status(self, mock_get):
        import httpx
        mock_get.side_effect = httpx.RequestError("connection refused")

        scan = ScanResult.objects.create(url="https://example.com")
        run_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == ScanStatus.FAILED
        assert scan.error_message != ""
