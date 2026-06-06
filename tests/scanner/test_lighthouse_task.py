import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest
from scanner.models import ScanResult


@pytest.fixture
def scan(db):
    return ScanResult.objects.create(url="https://example.com", findings=[], vibe_score=100)


SAMPLE_LH_JSON = {
    "audits": {
        "color-contrast": {"score": 0.4, "scoreDisplayMode": "binary"},
        "largest-contentful-paint": {"score": 0.7, "scoreDisplayMode": "numeric", "displayValue": "3.1 s"},
        "document-title": {"score": 1.0, "scoreDisplayMode": "binary"},
    },
    "categories": {
        "performance": {"score": 0.75},
        "accessibility": {"score": 0.6},
        "best-practices": {"score": 0.9},
        "seo": {"score": 0.95},
    },
}


@pytest.mark.django_db
def test_lighthouse_task_happy_path(scan):
    from scanner.tasks import run_lighthouse_scan

    fake_proc = MagicMock(returncode=0, stdout=json.dumps(SAMPLE_LH_JSON), stderr="")
    with patch("subprocess.run", return_value=fake_proc):
        run_lighthouse_scan(str(scan.id))

    scan.refresh_from_db()
    assert scan.deep_scan_status == "done"
    assert scan.deep_scan_started_at is not None
    assert scan.deep_scan_finished_at is not None
    assert scan.deep_scan_categories == {
        "performance": 75, "accessibility": 60,
        "best-practices": 90, "seo": 95,
    }
    finding_ids = {f["id"] for f in scan.deep_scan_findings}
    assert "lh-color-contrast" in finding_ids
    assert "lh-lcp" in finding_ids
    assert "lh-document-title" not in finding_ids  # score=1.0 → OK → excluded
