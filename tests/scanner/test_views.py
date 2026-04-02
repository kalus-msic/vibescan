from unittest.mock import patch
from django.test import TestCase, Client
from django.urls import reverse
from scanner.models import ScanResult, ScanStatus


class HomeViewTest(TestCase):

    def test_home_returns_200(self):
        response = self.client.get(reverse("scanner:home"))
        self.assertEqual(response.status_code, 200)

    @patch("scanner.views.run_scan.delay")
    def test_valid_url_creates_scan_and_redirects(self, mock_delay):
        response = self.client.post(reverse("scanner:home"), {"url": "https://example.com"})
        self.assertEqual(ScanResult.objects.count(), 1)
        scan = ScanResult.objects.first()
        self.assertRedirects(response, reverse("scanner:scan_detail", args=[scan.id]))
        mock_delay.assert_called_once_with(str(scan.id))

    def test_invalid_url_shows_form_error(self):
        response = self.client.post(reverse("scanner:home"), {"url": "not a valid hostname!!"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Nelze přeložit hostname")

    @patch("scanner.views.run_scan.delay")
    def test_url_without_scheme_works(self, mock_delay):
        response = self.client.post(reverse("scanner:home"), {"url": "example.com"})
        self.assertEqual(ScanResult.objects.count(), 1)
        scan = ScanResult.objects.first()
        self.assertEqual(scan.url, "https://example.com")
        self.assertRedirects(response, reverse("scanner:scan_detail", args=[scan.id]))


class ScanDetailViewTest(TestCase):

    def test_pending_scan_returns_200(self):
        scan = ScanResult.objects.create(url="https://example.com")
        response = self.client.get(reverse("scanner:scan_detail", args=[scan.id]))
        self.assertEqual(response.status_code, 200)

    def test_status_endpoint_returns_partial(self):
        scan = ScanResult.objects.create(
            url="https://example.com", status=ScanStatus.DONE, vibe_score=75, findings=[]
        )
        response = self.client.get(
            reverse("scanner:scan_status", args=[scan.id]),
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.status_code, 200)
