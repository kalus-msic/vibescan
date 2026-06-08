import pytest
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

    def test_txt_export_contains_ai_agent_header(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertIn("Jsi bezpečnostní konzultant", content)
        self.assertIn("Vyhodnoť relevanci", content)
        self.assertIn("Seřaď podle reálného dopadu", content)
        self.assertIn("Vysvětluj česky", content)

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

    def test_txt_export_hides_ok_findings_from_category_sections(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertNotIn("#### [OK]", content)
        self.assertNotIn("[OK] Strict-Transport-Security přítomen", content)

    def test_txt_export_has_ok_summary_section_with_titles(self):
        scan = _create_done_scan()
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertIn("## Co je v pořádku", content)
        self.assertIn("- Strict-Transport-Security přítomen", content)

    def test_txt_export_ok_summary_includes_detail_when_present(self):
        findings = [
            {
                "id": "title-ok",
                "title": "Titulek stránky nastaven",
                "description": "Stránka má titulek.",
                "severity": "ok",
                "category": "seo",
                "penalty": 0,
                "detail": "InnoVerse",
                "doc_url": None,
            },
        ]
        scan = _create_done_scan(findings=findings, vibe_score=100)
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertIn("- Titulek stránky nastaven — InnoVerse", content)

    def test_txt_export_omits_ok_section_when_no_ok_findings(self):
        findings = [
            {
                "id": "missing-csp",
                "title": "Chybí CSP",
                "description": "...",
                "severity": "critical",
                "category": "headers",
                "penalty": 20,
                "detail": None,
                "doc_url": None,
            },
        ]
        scan = _create_done_scan(findings=findings, vibe_score=80)
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        self.assertNotIn("## Co je v pořádku", content)

    def test_txt_export_hides_category_with_only_ok_findings(self):
        findings = [
            {
                "id": "https-ok",
                "title": "HTTPS aktivní",
                "description": "Web používá HTTPS.",
                "severity": "ok",
                "category": "ssl",
                "penalty": 0,
                "detail": None,
                "doc_url": None,
            },
            {
                "id": "missing-csp",
                "title": "Chybí CSP",
                "description": "...",
                "severity": "critical",
                "category": "headers",
                "penalty": 20,
                "detail": None,
                "doc_url": None,
            },
        ]
        scan = _create_done_scan(findings=findings, vibe_score=80)
        response = self.client.get(reverse("scanner:export_txt", args=[scan.id]))
        content = response.content.decode("utf-8")
        # ssl category has only an OK finding — should NOT appear as a category header
        self.assertNotIn("### Kategorie: ssl", content)
        # headers category has a critical finding — SHOULD appear
        self.assertIn("### Kategorie: headers", content)
        # the OK finding itself still goes into the summary section
        self.assertIn("- HTTPS aktivní", content)

    def test_txt_export_contains_tier_breakdown(self):
        scan = _create_done_scan(
            score_breakdown_computed=True,
            score_security=72, score_legal=85, score_seo=75,
        )
        from scanner.views import build_export_txt
        out = build_export_txt(scan)
        self.assertIn("Skóre podle priorit", out)
        self.assertIn("Bezpečnost: 72/100", out)
        self.assertIn("Právní: 85/100", out)
        self.assertIn("SEO a výkon: 75/100", out)

    def test_txt_export_old_scan_no_tier_breakdown(self):
        scan = _create_done_scan(score_breakdown_computed=False)
        from scanner.views import build_export_txt
        out = build_export_txt(scan)
        self.assertNotIn("Skóre podle priorit", out)
        # Fallback layout musí být přítomen
        self.assertIn("## Nálezy podle kategorie", out)

    def test_txt_export_severity_penalty_table_uses_new_values(self):
        scan = _create_done_scan()
        from scanner.views import build_export_txt
        out = build_export_txt(scan)
        # Po Task 2 musí být v tabulce -12/-5/-1 ne -20/-8/-2
        self.assertIn("-12", out)
        self.assertIn("-5", out)
        self.assertIn("-1", out)
        self.assertNotIn("| -20 ", out)


class OkFindingsFilterTest(TestCase):

    def test_ok_findings_returns_only_ok_severity(self):
        from scanner.templatetags.scan_tags import ok_findings
        findings = [
            {"severity": "critical", "title": "A"},
            {"severity": "ok", "title": "B"},
            {"severity": "warning", "title": "C"},
            {"severity": "ok", "title": "D"},
        ]
        result = ok_findings(findings)
        self.assertEqual([f["title"] for f in result], ["B", "D"])

    def test_ok_findings_empty_when_no_ok_severity(self):
        from scanner.templatetags.scan_tags import ok_findings
        findings = [{"severity": "critical", "title": "A"}]
        self.assertEqual(ok_findings(findings), [])

    def test_ok_findings_empty_list_returns_empty(self):
        from scanner.templatetags.scan_tags import ok_findings
        self.assertEqual(ok_findings([]), [])


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


@pytest.mark.django_db
def test_export_txt_includes_deep_scan_when_done():
    from scanner.models import ScanResult
    from scanner.views import build_export_txt
    scan = ScanResult.objects.create(
        url="https://example.com", status="done", vibe_score=72,
        findings=[{"id": "a", "title": "Fast finding", "category": "headers", "severity": "info", "description": "x"}],
        deep_scan_status="done",
        deep_scan_findings=[{"id": "lh-lcp", "title": "LCP pomalý", "category": "performance", "severity": "warning", "description": "LCP > 4 s"}],
        deep_scan_categories={"performance": 55, "accessibility": 90, "best-practices": 80, "seo": 95},
    )
    out = build_export_txt(scan)
    assert "Fast finding" in out
    assert "LCP pomalý" in out
    assert "Hluboký sken" in out or "Lighthouse" in out


@pytest.mark.django_db
def test_export_txt_warns_when_deep_scan_running():
    from scanner.models import ScanResult
    from scanner.views import build_export_txt
    scan = ScanResult.objects.create(
        url="https://example.com", status="done", vibe_score=78,
        findings=[],
        deep_scan_status="running",
    )
    out = build_export_txt(scan)
    assert "probíhá" in out.lower()


@pytest.mark.django_db
def test_export_txt_notes_failed_deep_scan():
    from scanner.models import ScanResult
    from scanner.views import build_export_txt
    scan = ScanResult.objects.create(
        url="https://example.com", status="done", vibe_score=78,
        findings=[],
        deep_scan_status="failed",
        deep_scan_error="Chrome crashed",
    )
    out = build_export_txt(scan)
    assert "selhal" in out.lower()


@pytest.mark.django_db
def test_export_txt_excludes_superseded_findings():
    from scanner.models import ScanResult
    from scanner.views import build_export_txt
    scan = ScanResult.objects.create(
        url="https://example.com", status="done", vibe_score=80,
        findings=[
            {"id": "missing-title", "title": "Fast: chybí title", "category": "seo", "severity": "warning", "description": "x"},
            {"id": "other", "title": "Other finding", "category": "headers", "severity": "info", "description": "x"},
        ],
        deep_scan_status="done",
        deep_scan_findings=[
            {"id": "lh-document-title", "title": "LH: chybí title", "category": "seo", "severity": "critical", "description": "x"},
        ],
    )
    out = build_export_txt(scan)
    assert "Fast: chybí title" not in out  # superseded
    assert "LH: chybí title" in out
    assert "Other finding" in out


@pytest.mark.django_db
def test_export_pdf_renders_with_deep_scan(client):
    from scanner.models import ScanResult
    scan = ScanResult.objects.create(
        url="https://example.com", status="done", vibe_score=72,
        findings=[],
        deep_scan_status="done",
        deep_scan_findings=[{"id": "lh-lcp", "title": "LCP pomalý", "category": "performance", "severity": "warning", "description": "x"}],
        deep_scan_categories={"performance": 55, "accessibility": 90, "best-practices": 80, "seo": 95},
    )
    response = client.get(reverse("scanner:export_pdf", kwargs={"pk": scan.id}))
    assert response.status_code == 200
    assert response["Content-Type"] == "application/pdf"
    # PDF is binary; just verify generation didn't crash
    assert len(response.content) > 1000


@pytest.mark.django_db
def test_export_txt_preview_matches_download():
    """The inline preview (template tag) must produce the same output as the downloadable file."""
    from scanner.models import ScanResult
    from scanner.views import build_export_txt
    from django.template import Template, Context

    scan = ScanResult.objects.create(
        url="https://example.com", status="done", vibe_score=80,
        findings=[{"id": "x", "title": "X", "category": "headers", "severity": "info", "description": "y"}],
        deep_scan_status="done",
        deep_scan_findings=[{"id": "lh-lcp", "title": "LCP", "category": "performance", "severity": "warning", "description": "z"}],
        deep_scan_categories={"performance": 50, "accessibility": 90, "best-practices": 80, "seo": 95},
    )
    download_text = build_export_txt(scan)
    preview_text = Template("{% load scan_tags %}{% export_txt_preview scan %}").render(Context({"scan": scan}))
    # Both should include Lighthouse content
    assert "LCP" in download_text
    assert "LCP" in preview_text
    # And the preview should be substring-identical or equal to the download (allow whitespace tolerance)
    assert preview_text.strip() == download_text.strip()


@pytest.mark.django_db
def test_export_pdf_excludes_superseded_fast_findings(client):
    """Fast finding superseded by Lighthouse should not appear in PDF body."""
    from scanner.models import ScanResult
    from urllib.parse import urlparse  # ensure available
    scan = ScanResult.objects.create(
        url="https://example.com", status="done", vibe_score=80,
        findings=[
            {"id": "missing-title", "title": "Fast finding: chybí title XYZUNIQUE", "category": "seo", "severity": "warning", "description": "x"},
        ],
        deep_scan_status="done",
        deep_scan_findings=[
            {"id": "lh-document-title", "title": "Lighthouse: chybí title ABCUNIQUE", "category": "seo", "severity": "critical", "description": "x"},
        ],
    )
    # Render the HTML template directly (faster than WeasyPrint roundtrip)
    from django.template.loader import render_to_string
    from scanner.score import _superseded_ids
    superseded = _superseded_ids(scan.deep_scan_findings or [])
    active = [f for f in scan.findings if not f.get("dismissed") and f.get("id") not in superseded]
    deep_active = [f for f in (scan.deep_scan_findings or []) if not f.get("dismissed")]

    def _group(findings):
        cats = {}
        for f in findings:
            cats.setdefault(f.get("category", "other"), []).append(f)
        return sorted(cats.items())

    html = render_to_string("scanner/export_pdf.html", {
        "scan": scan,
        "findings_by_category": _group(active),
        "deep_findings_by_category": _group(deep_active),
        "deep_categories": {},
        "deep_status": "done",
        "deep_error": "",
        "active_findings_filtered": active,
    })
    assert "XYZUNIQUE" not in html  # superseded — should be gone
    assert "ABCUNIQUE" in html  # Lighthouse finding present
