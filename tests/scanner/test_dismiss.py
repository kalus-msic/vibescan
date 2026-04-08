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
