import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest
from scanner.models import ScanResult


@pytest.fixture
def scan(db):
    return ScanResult.objects.create(
        url="https://example.com", findings=[], vibe_score=100, status="done",
    )


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
    with patch("subprocess.run", return_value=fake_proc), \
         patch("scanner.tasks.run_consent_check", return_value=[]):
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
    assert "90 s" in scan.deep_scan_error
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


CONSENT_F2 = {
    "id": "consent-reject-ineffective",
    "title": "Reject ineffective",
    "description": "x",
    "severity": "critical",
    "category": "tracking",
    "fix_url": "/guide/",
    "doc_url": None,
    "detail": "Google Analytics (_ga)",
    "supersedes_ids": ["tracking-no-consent", "missing-cookie-consent"],
}

FAST_WITH_BANNER = [
    {"id": "cookie-consent-ok", "severity": "ok", "category": "legal"},
    {"id": "tracking-no-consent", "severity": "warning", "category": "tracking"},
]


@pytest.fixture
def scan_with_banner(db):
    # Consistent with FAST_WITH_BANNER: security 95, overall round(97.5) = 98
    return ScanResult.objects.create(
        url="https://example.com",
        findings=list(FAST_WITH_BANNER),
        status="done",
        vibe_score=98,
        score_security=95,
    )


@pytest.fixture
def pending_scan(db):
    """Fast scan not finished yet when the deep task starts."""
    return ScanResult.objects.create(url="https://example.com", findings=[], status="running")


def _lh_ok():
    return MagicMock(returncode=0, stdout=json.dumps(SAMPLE_LH_JSON), stderr="")


def _finish_fast_scan(scan_pk):
    ScanResult.objects.filter(pk=scan_pk).update(
        findings=list(FAST_WITH_BANNER), status="done", vibe_score=98, score_security=95,
    )


def _assert_combined_scores(scan):
    # security: tracking-no-consent superseded, consent CRITICAL (-12) → 88
    # legal: lh-color-contrast CRITICAL (accessibility → legal, -12) → 88
    # seo: lh-lcp WARNING (-5) → 95
    # overall: 0.5×88 + 0.3×88 + 0.2×95 = 89.4 → 89
    assert (scan.score_security, scan.score_legal, scan.score_seo) == (88, 88, 95)
    assert scan.vibe_score == 89


@pytest.mark.django_db
def test_consent_check_appends_findings_and_rescores(scan_with_banner):
    from scanner.tasks import run_lighthouse_scan
    with patch("subprocess.run", return_value=_lh_ok()), \
         patch("scanner.tasks.run_consent_check", return_value=[dict(CONSENT_F2)]) as consent:
        run_lighthouse_scan(str(scan_with_banner.id))
    consent.assert_called_once_with("https://example.com", fast_ids=frozenset({"cookie-consent-ok", "tracking-no-consent"}))
    scan = scan_with_banner
    scan.refresh_from_db()
    ids = {f["id"] for f in scan.deep_scan_findings}
    assert {"lh-color-contrast", "consent-reject-ineffective"} <= ids
    assert scan.deep_scan_status == "done"
    assert scan.pre_deep_scan_score == 98
    _assert_combined_scores(scan)


@pytest.mark.django_db
def test_consent_check_runs_without_static_consent_findings(scan):
    """User decision: every deep scan with a finished fast scan gets the browser check."""
    from scanner.tasks import run_lighthouse_scan
    with patch("subprocess.run", return_value=_lh_ok()), \
         patch("scanner.tasks.run_consent_check", return_value=[]) as consent:
        run_lighthouse_scan(str(scan.id))
    consent.assert_called_once_with("https://example.com", fast_ids=frozenset())


@pytest.mark.django_db
def test_dismiss_during_consent_check_is_reflected_in_rescore(scan_with_banner):
    """A dismiss made while the (up to 90 s) consent check runs must be picked
    up by the rescore - not overwritten by findings read before the check started."""
    from scanner.tasks import run_lighthouse_scan

    def _consent_check_dismisses_tracking(url, fast_ids=frozenset()):
        dismissed = [dict(f) for f in FAST_WITH_BANNER]
        for f in dismissed:
            if f["id"] == "tracking-no-consent":
                f["dismissed"] = True
        ScanResult.objects.filter(pk=scan_with_banner.pk).update(findings=dismissed)
        return []

    with patch("subprocess.run", return_value=_lh_ok()), \
         patch("scanner.tasks.run_consent_check", side_effect=_consent_check_dismisses_tracking):
        run_lighthouse_scan(str(scan_with_banner.id))

    scan_with_banner.refresh_from_db()
    assert scan_with_banner.score_security == 100


@pytest.mark.django_db
def test_fast_scan_finishing_during_lighthouse_is_used(pending_scan):
    from scanner.tasks import run_lighthouse_scan

    def lighthouse_while_fast_finishes(*args, **kwargs):
        _finish_fast_scan(pending_scan.pk)
        return _lh_ok()

    with patch("subprocess.run", side_effect=lighthouse_while_fast_finishes), \
         patch("scanner.tasks.run_consent_check", return_value=[dict(CONSENT_F2)]) as consent, \
         patch("scanner.tasks.time.sleep") as sleep:
        run_lighthouse_scan(str(pending_scan.id))
    consent.assert_called_once()
    sleep.assert_not_called()
    pending_scan.refresh_from_db()
    assert pending_scan.findings == FAST_WITH_BANNER
    assert pending_scan.deep_scan_status == "done"
    _assert_combined_scores(pending_scan)


@pytest.mark.django_db
def test_waits_for_fast_scan_then_rescores(pending_scan):
    """Fast scan finishes only during the wait loop: consent runs, scores are combined."""
    from scanner.tasks import run_lighthouse_scan

    with patch("subprocess.run", return_value=_lh_ok()), \
         patch("scanner.tasks.run_consent_check", return_value=[dict(CONSENT_F2)]) as consent, \
         patch("scanner.tasks.time.sleep", side_effect=lambda _s: _finish_fast_scan(pending_scan.pk)) as sleep:
        run_lighthouse_scan(str(pending_scan.id))
    sleep.assert_called_once_with(2)
    consent.assert_called_once()
    pending_scan.refresh_from_db()
    assert pending_scan.deep_scan_status == "done"
    assert pending_scan.pre_deep_scan_score == 98
    _assert_combined_scores(pending_scan)


@pytest.mark.django_db
def test_fast_scan_never_finishing_fails_deep_scan(pending_scan):
    from scanner.tasks import run_lighthouse_scan
    with patch("subprocess.run", return_value=_lh_ok()), \
         patch("scanner.tasks.run_consent_check") as consent, \
         patch("scanner.tasks._FAST_SCAN_WAIT_SECONDS", 0), \
         patch("scanner.tasks.time.sleep"):
        run_lighthouse_scan(str(pending_scan.id))
    consent.assert_not_called()
    pending_scan.refresh_from_db()
    assert pending_scan.deep_scan_status == "failed"
    assert "nedoběhl" in pending_scan.deep_scan_error
    assert pending_scan.score_breakdown_computed is False
    assert pending_scan.pre_deep_scan_score is None


@pytest.mark.django_db
def test_consent_check_skipped_when_fast_scan_failed(scan_with_banner):
    from scanner.tasks import run_lighthouse_scan
    ScanResult.objects.filter(pk=scan_with_banner.pk).update(status="failed")
    with patch("subprocess.run", return_value=_lh_ok()), \
         patch("scanner.tasks.run_consent_check") as consent:
        run_lighthouse_scan(str(scan_with_banner.id))
    consent.assert_not_called()
    scan_with_banner.refresh_from_db()
    assert scan_with_banner.deep_scan_status == "done"


@pytest.mark.django_db
def test_failed_deep_scan_does_not_overwrite_fast_fields(pending_scan):
    from scanner.tasks import run_lighthouse_scan

    def failing_lighthouse_while_fast_finishes(*args, **kwargs):
        _finish_fast_scan(pending_scan.pk)
        return MagicMock(returncode=1, stdout="", stderr="Chrome crashed")

    with patch("subprocess.run", side_effect=failing_lighthouse_while_fast_finishes):
        run_lighthouse_scan(str(pending_scan.id))
    pending_scan.refresh_from_db()
    assert pending_scan.deep_scan_status == "failed"
    assert pending_scan.findings == FAST_WITH_BANNER
    assert pending_scan.status == "done"
    assert pending_scan.vibe_score == 98


@pytest.mark.django_db
def test_consent_check_crash_keeps_lighthouse_results(scan_with_banner):
    from scanner.tasks import run_lighthouse_scan
    with patch("subprocess.run", return_value=_lh_ok()), \
         patch("scanner.tasks.run_consent_check", side_effect=RuntimeError("boom")):
        run_lighthouse_scan(str(scan_with_banner.id))
    scan_with_banner.refresh_from_db()
    assert scan_with_banner.deep_scan_status == "done"
    ids = {f["id"] for f in scan_with_banner.deep_scan_findings}
    assert "lh-color-contrast" in ids
    assert not any(i.startswith("consent-") for i in ids)


@pytest.mark.django_db
def test_consent_check_not_run_when_lighthouse_fails(scan_with_banner):
    from scanner.tasks import run_lighthouse_scan
    failed = MagicMock(returncode=1, stdout="", stderr="Chrome crashed")
    with patch("subprocess.run", return_value=failed), \
         patch("scanner.tasks.run_consent_check") as consent:
        run_lighthouse_scan(str(scan_with_banner.id))
    consent.assert_not_called()
    scan_with_banner.refresh_from_db()
    assert scan_with_banner.deep_scan_status == "failed"


@pytest.mark.django_db
def test_retry_does_not_duplicate_consent_findings(scan_with_banner):
    from scanner.tasks import run_lighthouse_scan
    with patch("subprocess.run", return_value=_lh_ok()), \
         patch("scanner.tasks.run_consent_check", return_value=[dict(CONSENT_F2)]):
        run_lighthouse_scan(str(scan_with_banner.id))
        run_lighthouse_scan(str(scan_with_banner.id))
    scan_with_banner.refresh_from_db()
    consent_ids = [f["id"] for f in scan_with_banner.deep_scan_findings if f["id"].startswith("consent-")]
    assert consent_ids == ["consent-reject-ineffective"]


def test_lighthouse_task_time_limits_fit_consent_check():
    from scanner.tasks import run_lighthouse_scan
    assert run_lighthouse_scan.time_limit == 270
    assert run_lighthouse_scan.soft_time_limit == 240
