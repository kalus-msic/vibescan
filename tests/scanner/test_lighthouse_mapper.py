import pytest
from scanner.lighthouse_mapper import LighthouseMapper
from scanner.lighthouse_audits import AuditMap
from scanner.modules.base import Severity


@pytest.fixture
def mapper():
    return LighthouseMapper()


@pytest.fixture
def default_mapping():
    return AuditMap(
        finding_id="lh-test", title="t", description="d",
        category="seo", fix_url="/g/",
    )


def test_severity_score_one_is_ok(mapper, default_mapping):
    audit = {"score": 1.0, "scoreDisplayMode": "binary"}
    assert mapper._severity(audit, default_mapping) == Severity.OK


def test_severity_score_high_is_info(mapper, default_mapping):
    # 0.9 ≤ score < 1.0 → INFO
    audit = {"score": 0.95, "scoreDisplayMode": "numeric"}
    assert mapper._severity(audit, default_mapping) == Severity.INFO


def test_severity_score_mid_is_warning(mapper, default_mapping):
    # 0.5 ≤ score < 0.9 → WARNING
    audit = {"score": 0.7, "scoreDisplayMode": "numeric"}
    assert mapper._severity(audit, default_mapping) == Severity.WARNING


def test_severity_score_low_is_critical(mapper, default_mapping):
    # score < 0.5 → CRITICAL
    audit = {"score": 0.3, "scoreDisplayMode": "numeric"}
    assert mapper._severity(audit, default_mapping) == Severity.CRITICAL


def test_severity_not_applicable_is_skipped(mapper, default_mapping):
    audit = {"score": None, "scoreDisplayMode": "notApplicable"}
    assert mapper._severity(audit, default_mapping) is None


def test_severity_informative_is_info(mapper, default_mapping):
    audit = {"score": None, "scoreDisplayMode": "informative"}
    assert mapper._severity(audit, default_mapping) == Severity.INFO


def test_severity_null_score_is_skipped(mapper, default_mapping):
    audit = {"score": None, "scoreDisplayMode": "numeric"}
    assert mapper._severity(audit, default_mapping) is None


def test_severity_custom_thresholds(mapper):
    mapping = AuditMap(
        finding_id="lh-strict", title="t", description="d",
        category="seo", fix_url="/g/",
        warn_below=1.0, crit_below=0.8,  # stricter
    )
    audit = {"score": 0.85, "scoreDisplayMode": "numeric"}
    assert mapper._severity(audit, mapping) == Severity.WARNING
