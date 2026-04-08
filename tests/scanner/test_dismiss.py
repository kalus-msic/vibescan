import uuid
import copy
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from scanner.models import ScanResult, ScanStatus
from scanner.score import recalculate_from_findings_dicts


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
    {
        "id": "missing-referrer",
        "title": "Chybí Referrer-Policy",
        "description": "Bez Referrer-Policy hlavičky.",
        "severity": "info",
        "category": "headers",
        "penalty": 2,
        "fix_url": "/guide/#referrer",
        "detail": None,
        "doc_url": None,
    },
]

VALID_REASONS = ["not_applicable", "solved_differently", "false_positive", "other"]


def _create_done_scan(**kwargs):
    defaults = dict(
        url="https://example.com",
        status=ScanStatus.DONE,
        vibe_score=70,
        findings=copy.deepcopy(SAMPLE_FINDINGS),
        completed_at=timezone.now(),
    )
    defaults.update(kwargs)
    return ScanResult.objects.create(**defaults)


class RecalculateScoreTest(TestCase):

    def test_score_without_dismissed(self):
        score = recalculate_from_findings_dicts(SAMPLE_FINDINGS)
        # 100 - 20 (critical) - 8 (warning) - 2 (info) = 70
        self.assertEqual(score, 70)

    def test_score_excludes_dismissed_findings(self):
        findings = copy.deepcopy(SAMPLE_FINDINGS)
        findings[0]["dismissed"] = True  # critical, -20
        findings[0]["dismiss_reason"] = "false_positive"
        score = recalculate_from_findings_dicts(findings)
        # 100 - 8 (warning) - 2 (info) = 90
        self.assertEqual(score, 90)

    def test_score_floors_at_zero(self):
        many_critical = [
            {"id": f"c{i}", "severity": "critical", "penalty": 20}
            for i in range(10)
        ]
        score = recalculate_from_findings_dicts(many_critical)
        self.assertEqual(score, 0)

    def test_score_all_dismissed_returns_100(self):
        findings = copy.deepcopy(SAMPLE_FINDINGS)
        for f in findings:
            f["dismissed"] = True
            f["dismiss_reason"] = "other"
        score = recalculate_from_findings_dicts(findings)
        self.assertEqual(score, 100)


from scanner.templatetags.scan_tags import active_findings, dismissed_findings, dismiss_reason_label


class TemplateFilterTest(TestCase):

    def test_active_findings_excludes_dismissed(self):
        findings = copy.deepcopy(SAMPLE_FINDINGS)
        findings[0]["dismissed"] = True
        result = active_findings(findings)
        self.assertEqual(len(result), 3)
        self.assertTrue(all(f["id"] != "missing-csp" for f in result))

    def test_active_findings_returns_all_when_none_dismissed(self):
        result = active_findings(SAMPLE_FINDINGS)
        self.assertEqual(len(result), 4)

    def test_dismissed_findings_returns_only_dismissed(self):
        findings = copy.deepcopy(SAMPLE_FINDINGS)
        findings[0]["dismissed"] = True
        findings[0]["dismiss_reason"] = "false_positive"
        result = dismissed_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "missing-csp")

    def test_dismissed_findings_returns_empty_when_none_dismissed(self):
        result = dismissed_findings(SAMPLE_FINDINGS)
        self.assertEqual(len(result), 0)

    def test_dismiss_reason_label_translates_reasons(self):
        self.assertEqual(dismiss_reason_label("not_applicable"), "Nepoužívám tuto funkci")
        self.assertEqual(dismiss_reason_label("solved_differently"), "Řeším jinak")
        self.assertEqual(dismiss_reason_label("false_positive"), "Falešný poplach")
        self.assertEqual(dismiss_reason_label("other"), "Jiný důvod")

    def test_dismiss_reason_label_returns_value_for_unknown(self):
        self.assertEqual(dismiss_reason_label("unknown_reason"), "unknown_reason")


class DismissFindingTest(TestCase):

    def test_dismiss_sets_dismissed_and_reason(self):
        scan = _create_done_scan()
        response = self.client.post(
            reverse("scanner:dismiss_finding", args=[scan.id, "missing-csp"]),
            {"reason": "false_positive"},
        )
        self.assertEqual(response.status_code, 200)
        scan.refresh_from_db()
        finding = next(f for f in scan.findings if f["id"] == "missing-csp")
        self.assertTrue(finding["dismissed"])
        self.assertEqual(finding["dismiss_reason"], "false_positive")

    def test_dismiss_recalculates_vibe_score(self):
        scan = _create_done_scan()
        self.assertEqual(scan.vibe_score, 70)
        self.client.post(
            reverse("scanner:dismiss_finding", args=[scan.id, "missing-csp"]),
            {"reason": "not_applicable"},
        )
        scan.refresh_from_db()
        # 100 - 8 (warning) - 2 (info) = 90 (critical dismissed)
        self.assertEqual(scan.vibe_score, 90)

    def test_dismiss_returns_htmx_partial(self):
        scan = _create_done_scan()
        response = self.client.post(
            reverse("scanner:dismiss_finding", args=[scan.id, "missing-csp"]),
            {"reason": "other"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "scan-content")

    def test_dismiss_requires_valid_reason(self):
        scan = _create_done_scan()
        response = self.client.post(
            reverse("scanner:dismiss_finding", args=[scan.id, "missing-csp"]),
            {"reason": "invalid_reason"},
        )
        self.assertEqual(response.status_code, 400)

    def test_dismiss_requires_reason_field(self):
        scan = _create_done_scan()
        response = self.client.post(
            reverse("scanner:dismiss_finding", args=[scan.id, "missing-csp"]),
            {},
        )
        self.assertEqual(response.status_code, 400)

    def test_dismiss_404_for_nonexistent_finding(self):
        scan = _create_done_scan()
        response = self.client.post(
            reverse("scanner:dismiss_finding", args=[scan.id, "nonexistent-id"]),
            {"reason": "other"},
        )
        self.assertEqual(response.status_code, 404)

    def test_dismiss_404_for_ephemeral_scan(self):
        scan = _create_done_scan(ephemeral=True)
        response = self.client.post(
            reverse("scanner:dismiss_finding", args=[scan.id, "missing-csp"]),
            {"reason": "other"},
        )
        self.assertEqual(response.status_code, 404)

    def test_dismiss_404_for_pending_scan(self):
        scan = ScanResult.objects.create(url="https://example.com", status=ScanStatus.PENDING)
        response = self.client.post(
            reverse("scanner:dismiss_finding", args=[scan.id, "missing-csp"]),
            {"reason": "other"},
        )
        self.assertEqual(response.status_code, 404)

    def test_dismiss_all_valid_reasons(self):
        for reason in VALID_REASONS:
            scan = _create_done_scan()
            response = self.client.post(
                reverse("scanner:dismiss_finding", args=[scan.id, "missing-csp"]),
                {"reason": reason},
            )
            self.assertEqual(response.status_code, 200, f"Failed for reason: {reason}")


class RestoreFindingTest(TestCase):

    def _dismiss_finding(self, scan, finding_id, reason="other"):
        for f in scan.findings:
            if f["id"] == finding_id:
                f["dismissed"] = True
                f["dismiss_reason"] = reason
        scan.save(update_fields=["findings"])

    def test_restore_removes_dismissed_keys(self):
        scan = _create_done_scan()
        self._dismiss_finding(scan, "missing-csp")
        response = self.client.post(
            reverse("scanner:restore_finding", args=[scan.id, "missing-csp"]),
        )
        self.assertEqual(response.status_code, 200)
        scan.refresh_from_db()
        finding = next(f for f in scan.findings if f["id"] == "missing-csp")
        self.assertNotIn("dismissed", finding)
        self.assertNotIn("dismiss_reason", finding)

    def test_restore_recalculates_vibe_score(self):
        scan = _create_done_scan(vibe_score=90)
        self._dismiss_finding(scan, "missing-csp")
        self.client.post(
            reverse("scanner:restore_finding", args=[scan.id, "missing-csp"]),
        )
        scan.refresh_from_db()
        # Back to original: 100 - 20 - 8 - 2 = 70
        self.assertEqual(scan.vibe_score, 70)

    def test_restore_returns_htmx_partial(self):
        scan = _create_done_scan()
        self._dismiss_finding(scan, "missing-csp")
        response = self.client.post(
            reverse("scanner:restore_finding", args=[scan.id, "missing-csp"]),
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "scan-content")

    def test_restore_404_for_nonexistent_finding(self):
        scan = _create_done_scan()
        response = self.client.post(
            reverse("scanner:restore_finding", args=[scan.id, "nonexistent-id"]),
        )
        self.assertEqual(response.status_code, 404)

    def test_restore_404_for_ephemeral_scan(self):
        scan = _create_done_scan(ephemeral=True)
        self._dismiss_finding(scan, "missing-csp")
        response = self.client.post(
            reverse("scanner:restore_finding", args=[scan.id, "missing-csp"]),
        )
        self.assertEqual(response.status_code, 404)
