from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from scanner.models import ScanResult, ScanStatus


SAMPLE_FINDINGS = [
    {
        "id": "missing-csp",
        "title": "Chybí Content-Security-Policy",
        "description": "Bez CSP hlavičky je web náchylný na XSS útoky.",
        "severity": "critical",
        "category": "headers",
        "penalty": 20,
        "fix_url": "/guide/#csp",
        "detail": "Header nenalezen",
        "doc_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    {
        "id": "hsts-ok",
        "title": "Strict-Transport-Security přítomen",
        "description": "HSTS je správně nakonfigurován.",
        "severity": "ok",
        "category": "headers",
        "penalty": 0,
        "fix_url": "/guide/",
        "detail": None,
        "doc_url": None,
    },
    {
        "id": "no-dmarc",
        "title": "Chybí DMARC záznam",
        "description": "DNS neobsahuje DMARC záznam.",
        "severity": "warning",
        "category": "dns",
        "penalty": 8,
        "fix_url": "/guide/#dmarc",
        "detail": None,
        "doc_url": "https://developer.mozilla.org/en-US/docs/Glossary/DMARC",
    },
]


def _create_done_scan(**kwargs):
    defaults = dict(
        url="https://example.com",
        status=ScanStatus.DONE,
        vibe_score=72,
        findings=SAMPLE_FINDINGS,
        completed_at=timezone.now(),
    )
    defaults.update(kwargs)
    return ScanResult.objects.create(**defaults)


class TxtExportTest(TestCase):

    def test_txt_export_returns_200_with_text_content_type(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")

    def test_txt_export_has_download_filename(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        self.assertIn("vibescan-report-example.com.txt", response["Content-Disposition"])

    def test_txt_export_contains_all_findings_including_ok(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertIn("Chybí Content-Security-Policy", content)
        self.assertIn("Strict-Transport-Security přítomen", content)
        self.assertIn("Chybí DMARC záznam", content)

    def test_txt_export_contains_ai_context_note(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertIn("nemusí být problém v kontextu", content)

    def test_txt_export_contains_score_and_url(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertIn("https://example.com", content)
        self.assertIn("72/100", content)

    def test_txt_export_groups_by_category(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertIn("### Kategorie: headers", content)
        self.assertIn("### Kategorie: dns", content)

    def test_txt_export_404_for_pending_scan(self):
        scan = ScanResult.objects.create(url="https://example.com", status=ScanStatus.PENDING)
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        self.assertEqual(response.status_code, 404)

    def test_txt_export_404_for_nonexistent_scan(self):
        import uuid
        response = self.client.get(
            reverse("scanner:export_txt", args=[uuid.uuid4()])
        )
        self.assertEqual(response.status_code, 404)


class PdfExportTest(TestCase):

    def test_pdf_export_returns_200_with_pdf_content_type(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_pdf", args=[scan.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")

    def test_pdf_export_has_download_filename(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_pdf", args=[scan.id]))
        self.assertIn("vibescan-report-example.com.pdf", response["Content-Disposition"])

    def test_pdf_export_starts_with_pdf_magic_bytes(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_pdf", args=[scan.id]))
        self.assertTrue(response.content[:5] == b"%PDF-")

    def test_pdf_export_404_for_pending_scan(self):
        scan = ScanResult.objects.create(url="https://example.com", status=ScanStatus.PENDING)
        response = self.client.get(reverse("scanner:export_pdf", args=[scan.id]))
        self.assertEqual(response.status_code, 404)

    def test_pdf_export_404_for_nonexistent_scan(self):
        import uuid
        response = self.client.get(
            reverse("scanner:export_pdf", args=[uuid.uuid4()])
        )
        self.assertEqual(response.status_code, 404)
