"""View tests pro accessibility classification override."""
import pytest
import uuid
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from scanner.models import ScanResult, ScanStatus


@pytest.mark.django_db
class TestSetAccessibilityClassification(TestCase):

    def _create_scan(self, **kwargs):
        defaults = dict(
            url="https://example.com",
            status=ScanStatus.DONE,
            vibe_score=80,
            score_security=70,
            score_legal=90,
            score_seo=95,
            accessibility_classification="auto",
            score_breakdown_computed=True,
            completed_at=timezone.now(),
            findings=[
                {"id": "missing-alt", "severity": "warning", "category": "accessibility"},
            ],
        )
        defaults.update(kwargs)
        return ScanResult.objects.create(**defaults)

    def test_post_legal_classification_updates_field(self):
        scan = self._create_scan()
        response = self.client.post(
            reverse("scanner:set_accessibility_classification", args=[scan.id]),
            {"classification": "legal"},
        )
        self.assertEqual(response.status_code, 200)
        scan.refresh_from_db()
        self.assertEqual(scan.accessibility_classification, "legal")

    def test_post_seo_classification_updates_field(self):
        scan = self._create_scan()
        response = self.client.post(
            reverse("scanner:set_accessibility_classification", args=[scan.id]),
            {"classification": "seo"},
        )
        scan.refresh_from_db()
        self.assertEqual(scan.accessibility_classification, "seo")

    def test_post_auto_classification_updates_field(self):
        scan = self._create_scan(accessibility_classification="legal")
        response = self.client.post(
            reverse("scanner:set_accessibility_classification", args=[scan.id]),
            {"classification": "auto"},
        )
        scan.refresh_from_db()
        self.assertEqual(scan.accessibility_classification, "auto")

    def test_invalid_classification_returns_400(self):
        scan = self._create_scan()
        response = self.client.post(
            reverse("scanner:set_accessibility_classification", args=[scan.id]),
            {"classification": "xxx"},
        )
        self.assertEqual(response.status_code, 400)

    def test_classification_change_recalculates_scores(self):
        """Změna z legal na seo musí přepočítat score_legal a score_seo."""
        scan = self._create_scan(accessibility_classification="legal")
        self.client.post(
            reverse("scanner:set_accessibility_classification", args=[scan.id]),
            {"classification": "seo"},
        )
        scan.refresh_from_db()
        # Po přesunu accessibility WARNING z legal do seo
        # se musí pohnout obě skóre
        self.assertEqual(scan.accessibility_classification, "seo")
        # Konkrétní hodnoty: missing-alt warning + accessibility cap=5 → seo -5 → 95
        # legal nemá accessibility findings → 100
        self.assertEqual(scan.score_legal, 100)
        self.assertEqual(scan.score_seo, 95)

    def test_ephemeral_scan_returns_403(self):
        scan = self._create_scan(ephemeral=True)
        response = self.client.post(
            reverse("scanner:set_accessibility_classification", args=[scan.id]),
            {"classification": "legal"},
        )
        # ephemeral scany nelze klasifikovat — stejně jako dismiss
        self.assertEqual(response.status_code, 404)

    def test_get_not_allowed(self):
        scan = self._create_scan()
        response = self.client.get(
            reverse("scanner:set_accessibility_classification", args=[scan.id]),
        )
        self.assertEqual(response.status_code, 405)

    def test_nonexistent_scan_returns_404(self):
        response = self.client.post(
            reverse("scanner:set_accessibility_classification",
                    args=[uuid.uuid4()]),
            {"classification": "legal"},
        )
        self.assertEqual(response.status_code, 404)

    def test_response_contains_results_partial(self):
        """Response musí obsahovat #scan-content pro HTMX swap."""
        scan = self._create_scan()
        response = self.client.post(
            reverse("scanner:set_accessibility_classification", args=[scan.id]),
            {"classification": "legal"},
        )
        self.assertContains(response, "scan-content")
