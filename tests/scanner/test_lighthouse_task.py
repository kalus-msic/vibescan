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


@pytest.mark.django_db
def test_lighthouse_task_timeout(scan):
    from scanner.tasks import run_lighthouse_scan
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="lighthouse", timeout=60)):
        run_lighthouse_scan(str(scan.id))
    scan.refresh_from_db()
    assert scan.deep_scan_status == "timeout"
    assert "60 s" in scan.deep_scan_error
    assert scan.deep_scan_findings == []
    assert scan.deep_scan_categories == {}


@pytest.mark.django_db
def test_lighthouse_task_nonzero_exit(scan):
    from scanner.tasks import run_lighthouse_scan
    fake_proc = MagicMock(returncode=1, stdout="", stderr="Chrome crashed")
    with patch("subprocess.run", return_value=fake_proc):
        run_lighthouse_scan(str(scan.id))
    scan.refresh_from_db()
    assert scan.deep_scan_status == "failed"
    assert "Chrome crashed" in scan.deep_scan_error


@pytest.mark.django_db
def test_lighthouse_task_invalid_json(scan):
    from scanner.tasks import run_lighthouse_scan
    fake_proc = MagicMock(returncode=0, stdout="not-json-at-all", stderr="")
    with patch("subprocess.run", return_value=fake_proc):
        run_lighthouse_scan(str(scan.id))
    scan.refresh_from_db()
    assert scan.deep_scan_status == "failed"
    assert "JSON" in scan.deep_scan_error


@pytest.mark.django_db
def test_lighthouse_task_runtime_error_in_output(scan):
    from scanner.tasks import run_lighthouse_scan
    data = {"runtimeError": {"code": "NO_FCP", "message": "Page did not paint"}, "audits": {}, "categories": {}}
    fake_proc = MagicMock(returncode=0, stdout=json.dumps(data), stderr="")
    with patch("subprocess.run", return_value=fake_proc):
        run_lighthouse_scan(str(scan.id))
    scan.refresh_from_db()
    assert scan.deep_scan_status == "failed"
    assert "Page did not paint" in scan.deep_scan_error


@pytest.mark.django_db
def test_lighthouse_task_missing_scan_silent(db):
    """Task on nonexistent scan ID returns silently — no exception."""
    import uuid
    from scanner.tasks import run_lighthouse_scan
    # Should not raise
    run_lighthouse_scan(str(uuid.uuid4()))


@pytest.mark.django_db
def test_failure_does_not_overwrite_vibe_score(scan):
    """If Lighthouse fails, the existing vibe_score (from fast pipeline) must stay."""
    from scanner.tasks import run_lighthouse_scan
    scan.vibe_score = 78
    scan.save()
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="lighthouse", timeout=60)):
        run_lighthouse_scan(str(scan.id))
    scan.refresh_from_db()
    assert scan.vibe_score == 78  # untouched
