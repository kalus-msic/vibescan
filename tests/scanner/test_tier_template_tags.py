"""Testy template tagů pro 3-tier zobrazení."""
import pytest
from scanner.templatetags.scan_tags import (
    findings_by_tier,
    tier_label,
    tier_color,
    has_breakdown,
)


class _FakeScan:
    def __init__(self, score_breakdown_computed=True, accessibility_classification="auto"):
        self.score_breakdown_computed = score_breakdown_computed
        self.accessibility_classification = accessibility_classification


def _d(fid: str, severity: str, category: str) -> dict:
    return {"id": fid, "severity": severity, "category": category}


class TestFindingsByTier:
    def test_security_findings_in_security_tier(self):
        findings = [
            _d("missing-csp", "critical", "headers"),
            _d("cookie-no-secure", "warning", "cookies"),
            _d("missing-spf", "warning", "dns"),
        ]
        result = findings_by_tier(findings, "legal")
        assert len(result["security"]) == 3
        assert result["legal"] == []
        assert result["seo"] == []

    def test_legal_findings_in_legal_tier(self):
        findings = [_d("no-consent", "info", "legal")]
        result = findings_by_tier(findings, "legal")
        assert len(result["legal"]) == 1
        assert result["security"] == []
        assert result["seo"] == []

    def test_seo_findings_in_seo_tier(self):
        findings = [
            _d("missing-canonical", "info", "seo"),
            _d("lh-lcp", "warning", "performance"),
            _d("missing-og", "info", "meta"),
        ]
        result = findings_by_tier(findings, "legal")
        assert len(result["seo"]) == 3

    def test_accessibility_routes_to_legal_when_legal_tier(self):
        findings = [_d("missing-alt", "warning", "accessibility")]
        result = findings_by_tier(findings, "legal")
        assert len(result["legal"]) == 1
        assert result["seo"] == []

    def test_accessibility_routes_to_seo_when_seo_tier(self):
        findings = [_d("missing-alt", "warning", "accessibility")]
        result = findings_by_tier(findings, "seo")
        assert len(result["seo"]) == 1
        assert result["legal"] == []

    def test_unknown_category_goes_to_seo(self):
        findings = [_d("x", "info", "unknown_module")]
        result = findings_by_tier(findings, "legal")
        assert len(result["seo"]) == 1


class TestTierLabel:
    def test_security_label(self):
        assert tier_label("security") == "Bezpečnost"

    def test_legal_label(self):
        assert tier_label("legal") == "Právní"

    def test_seo_label(self):
        assert tier_label("seo") == "SEO a výkon"

    def test_unknown_returns_input(self):
        assert tier_label("xxx") == "xxx"


class TestTierColor:
    def test_security_color(self):
        assert tier_color("security") == "red"

    def test_legal_color(self):
        assert tier_color("legal") == "amber"

    def test_seo_color(self):
        assert tier_color("seo") == "blue"

    def test_unknown_returns_slate(self):
        assert tier_color("xxx") == "slate"


class TestHasBreakdown:
    def test_true_when_computed_flag_set(self):
        scan = _FakeScan(score_breakdown_computed=True)
        assert has_breakdown(scan) is True

    def test_false_when_computed_flag_unset(self):
        scan = _FakeScan(score_breakdown_computed=False)
        assert has_breakdown(scan) is False


from scanner.templatetags.scan_tags import dict_get


class TestDictGet:
    def test_returns_value_for_known_key(self):
        d = {"security": [1, 2], "legal": [3]}
        assert dict_get(d, "security") == [1, 2]

    def test_returns_empty_list_for_missing_key(self):
        d = {"security": [1]}
        assert dict_get(d, "missing") == []

    def test_handles_none(self):
        assert dict_get(None, "key") == []
