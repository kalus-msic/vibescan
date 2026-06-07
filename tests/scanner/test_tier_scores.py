"""Testy 3-tier skórovacího engine (Bezpečnost / Právní / SEO)."""
from scanner.modules.base import Finding, Severity
from scanner.score import (
    CATEGORY_TO_TIER,
    TIER_WEIGHTS,
)


def test_category_to_tier_security_categories():
    for cat in ["headers", "cookies", "dns", "forms", "tech", "cors",
                "sri", "secrets", "ssl_check", "tracking", "html",
                "best-practices"]:
        assert CATEGORY_TO_TIER[cat] == "security", f"{cat} should be security"


def test_category_to_tier_legal_categories():
    assert CATEGORY_TO_TIER["legal"] == "legal"


def test_category_to_tier_seo_categories():
    for cat in ["seo", "meta", "performance"]:
        assert CATEGORY_TO_TIER[cat] == "seo"


def test_accessibility_not_in_static_mapping():
    assert "accessibility" not in CATEGORY_TO_TIER


def test_tier_weights_sum_to_one():
    assert abs(sum(TIER_WEIGHTS.values()) - 1.0) < 1e-9
    assert TIER_WEIGHTS["security"] == 0.5
    assert TIER_WEIGHTS["legal"] == 0.3
    assert TIER_WEIGHTS["seo"] == 0.2


from scanner.score import calculate_tier_scores, _resolve_tier


def _f(category: str, severity: Severity) -> Finding:
    return Finding(id=f"t-{category}", title="t", description="",
                   severity=severity, category=category)


class TestResolveTier:
    def test_security_category_resolves_to_security(self):
        assert _resolve_tier("headers", accessibility_tier="legal") == "security"

    def test_legal_category_resolves_to_legal(self):
        assert _resolve_tier("legal", accessibility_tier="legal") == "legal"

    def test_seo_category_resolves_to_seo(self):
        assert _resolve_tier("seo", accessibility_tier="legal") == "seo"

    def test_performance_resolves_to_seo(self):
        assert _resolve_tier("performance", accessibility_tier="legal") == "seo"

    def test_accessibility_routes_to_legal_when_legal_tier(self):
        assert _resolve_tier("accessibility", accessibility_tier="legal") == "legal"

    def test_accessibility_routes_to_seo_when_seo_tier(self):
        assert _resolve_tier("accessibility", accessibility_tier="seo") == "seo"

    def test_unknown_category_defaults_to_seo(self):
        """Bezpečný default — neznámé kategorie nepenalizují bezpečnost."""
        assert _resolve_tier("unknown_module", accessibility_tier="legal") == "seo"


class TestCalculateTierScores:
    def test_no_findings_all_tiers_100(self):
        scores = calculate_tier_scores([], accessibility_tier="legal")
        assert scores == {"security": 100, "legal": 100, "seo": 100}

    def test_security_finding_only_affects_security(self):
        findings = [_f("headers", Severity.CRITICAL)]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # CRITICAL=12, headers cap=15, pod capem
        assert scores["security"] == 88
        assert scores["legal"] == 100
        assert scores["seo"] == 100

    def test_legal_finding_only_affects_legal(self):
        findings = [_f("legal", Severity.WARNING)]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # WARNING=5, legal cap=4, capped na 4
        assert scores["security"] == 100
        assert scores["legal"] == 96
        assert scores["seo"] == 100

    def test_seo_finding_only_affects_seo(self):
        findings = [_f("seo", Severity.CRITICAL)]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # CRITICAL=12, seo cap=3, capped na 3
        assert scores["security"] == 100
        assert scores["legal"] == 100
        assert scores["seo"] == 97

    def test_accessibility_with_legal_tier_affects_legal(self):
        findings = [_f("accessibility", Severity.WARNING)]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # WARNING=5, accessibility cap=5, capped na 5
        assert scores["security"] == 100
        assert scores["legal"] == 95
        assert scores["seo"] == 100

    def test_accessibility_with_seo_tier_affects_seo(self):
        findings = [_f("accessibility", Severity.WARNING)]
        scores = calculate_tier_scores(findings, accessibility_tier="seo")
        assert scores["security"] == 100
        assert scores["legal"] == 100
        assert scores["seo"] == 95

    def test_per_category_cap_applied_within_tier(self):
        """Cap se aplikuje per kategorie i v tier kontextu."""
        findings = [
            _f("cookies", Severity.WARNING),
            _f("cookies", Severity.WARNING),
            _f("cookies", Severity.WARNING),
        ]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # 3×5=15 raw, cookies cap=10 → security -10 → 90
        assert scores["security"] == 90

    def test_tier_score_floors_at_zero(self):
        findings = [_f("secrets", Severity.CRITICAL)] * 20
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # secrets nemá cap → 20×12=240, floor 0
        assert scores["security"] == 0

    def test_mixed_findings_split_correctly(self):
        findings = [
            _f("headers", Severity.CRITICAL),     # security -12
            _f("legal", Severity.WARNING),        # legal -5 → cap 4
            _f("seo", Severity.INFO),             # seo -1
            _f("accessibility", Severity.WARNING),  # legal -5 (cap 5)
        ]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        assert scores["security"] == 88  # 100-12
        assert scores["legal"] == 91     # 100 - 4 (legal cap) - 5 (accessibility cap)
        assert scores["seo"] == 99       # 100-1
