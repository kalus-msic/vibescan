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


def test_severity_max_severity_warning_caps_critical(mapper):
    """Per-audit strop (např. heading-order = moderate WCAG) sníží CRITICAL na WARNING."""
    capped = AuditMap(
        finding_id="lh-x", title="t", description="d",
        category="accessibility", fix_url="/g/",
        max_severity="warning",
    )
    audit = {"score": 0.0, "scoreDisplayMode": "binary"}  # by default → CRITICAL
    assert mapper._severity(audit, capped) == Severity.WARNING


def test_severity_max_severity_does_not_inflate(mapper):
    """Strop nesmí severity zvyšovat — INFO zůstane INFO i s max_severity=warning."""
    capped = AuditMap(
        finding_id="lh-x", title="t", description="d",
        category="accessibility", fix_url="/g/",
        max_severity="warning",
    )
    audit = {"score": 0.95, "scoreDisplayMode": "numeric"}  # → INFO
    assert mapper._severity(audit, capped) == Severity.INFO


def test_heading_order_capped_at_warning(mapper):
    """Regrese: heading-order musí být max WARNING (best practice, ne blocker)."""
    from scanner.lighthouse_audits import LIGHTHOUSE_AUDIT_MAP
    mapping = LIGHTHOUSE_AUDIT_MAP["heading-order"]
    audit = {"score": 0.0, "scoreDisplayMode": "binary"}
    assert mapper._severity(audit, mapping) == Severity.WARNING


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


LH_FIXTURE = {
    "audits": {
        "document-title": {
            "id": "document-title",
            "title": "Document doesn't have a <title>",
            "score": 0,
            "scoreDisplayMode": "binary",
            "details": {"items": []},
        },
        "color-contrast": {
            "id": "color-contrast",
            "title": "Background and foreground colors do not have sufficient contrast",
            "score": 0.6,
            "scoreDisplayMode": "binary",
            "details": {"items": [{"node": {"snippet": "<p>x</p>"}}, {"node": {"snippet": "<a>y</a>"}}]},
        },
        "meta-description": {
            "id": "meta-description",
            "score": 1.0,
            "scoreDisplayMode": "binary",
        },
        "largest-contentful-paint": {
            "id": "largest-contentful-paint",
            "score": 0.4,
            "scoreDisplayMode": "numeric",
            "numericValue": 4200,
            "displayValue": "4.2 s",
        },
        "robots-txt": {
            "id": "robots-txt",
            "score": None,
            "scoreDisplayMode": "notApplicable",
        },
        "unknown-audit-not-in-allowlist": {
            "id": "unknown-audit-not-in-allowlist",
            "score": 0.1,
            "scoreDisplayMode": "binary",
        },
    },
    "categories": {
        "performance": {"score": 0.55, "title": "Performance"},
        "accessibility": {"score": 0.78, "title": "Accessibility"},
        "best-practices": {"score": 0.92, "title": "Best Practices"},
        "seo": {"score": 0.66, "title": "SEO"},
    },
}


def test_map_returns_findings_and_categories(mapper):
    findings, categories = mapper.map(LH_FIXTURE)
    assert isinstance(findings, list)
    assert isinstance(categories, dict)


def test_map_categories_rounded_to_int(mapper):
    _, categories = mapper.map(LH_FIXTURE)
    assert categories == {
        "performance": 55,
        "accessibility": 78,
        "best-practices": 92,
        "seo": 66,
    }


def test_map_excludes_ok_findings(mapper):
    """Score == 1.0 → OK, but OK findings are not emitted (noise reduction)."""
    findings, _ = mapper.map(LH_FIXTURE)
    ids = [f["id"] for f in findings]
    assert "lh-meta-description" not in ids  # had score=1.0


def test_map_excludes_not_applicable(mapper):
    findings, _ = mapper.map(LH_FIXTURE)
    ids = [f["id"] for f in findings]
    assert "lh-robots-txt" not in ids


def test_map_excludes_unknown_audits(mapper):
    """Audits not in LIGHTHOUSE_AUDIT_MAP are ignored entirely."""
    findings, _ = mapper.map(LH_FIXTURE)
    ids = [f["id"] for f in findings]
    assert "unknown-audit-not-in-allowlist" not in ids


def test_map_finding_has_required_keys(mapper):
    findings, _ = mapper.map(LH_FIXTURE)
    f = next(x for x in findings if x["id"] == "lh-color-contrast")
    assert f["title"] == "Nedostatečný kontrast textu"
    assert f["category"] == "accessibility"
    assert f["severity"] == "warning"  # 0.6 → WARNING
    assert f["fix_url"].startswith("/guide/")


def test_map_severities_correct(mapper):
    findings, _ = mapper.map(LH_FIXTURE)
    by_id = {f["id"]: f for f in findings}
    assert by_id["lh-document-title"]["severity"] == "critical"  # 0 → CRITICAL
    assert by_id["lh-color-contrast"]["severity"] == "warning"   # 0.6 → WARNING
    assert by_id["lh-lcp"]["severity"] == "critical"             # 0.4 → CRITICAL


def test_map_handles_missing_categories(mapper):
    data = {"audits": {}, "categories": {"performance": {"score": None}}}
    _, categories = mapper.map(data)
    assert categories == {}  # null scores skipped
