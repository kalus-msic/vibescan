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
        # CRITICAL=12 raw
        assert scores["security"] == 88
        assert scores["legal"] == 100
        assert scores["seo"] == 100

    def test_legal_finding_only_affects_legal(self):
        findings = [_f("legal", Severity.WARNING)]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # WARNING=5 raw, žádný cap
        assert scores["security"] == 100
        assert scores["legal"] == 95
        assert scores["seo"] == 100

    def test_seo_finding_only_affects_seo(self):
        findings = [_f("seo", Severity.CRITICAL)]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # CRITICAL=12 raw, žádný cap
        assert scores["security"] == 100
        assert scores["legal"] == 100
        assert scores["seo"] == 88

    def test_accessibility_with_legal_tier_affects_legal(self):
        findings = [_f("accessibility", Severity.WARNING)]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # WARNING=5 raw
        assert scores["security"] == 100
        assert scores["legal"] == 95
        assert scores["seo"] == 100

    def test_accessibility_with_seo_tier_affects_seo(self):
        findings = [_f("accessibility", Severity.WARNING)]
        scores = calculate_tier_scores(findings, accessibility_tier="seo")
        assert scores["security"] == 100
        assert scores["legal"] == 100
        assert scores["seo"] == 95

    def test_no_per_category_cap(self):
        """Per-category caps byly zrušeny — surová suma severit se započítá."""
        findings = [
            _f("cookies", Severity.WARNING),
            _f("cookies", Severity.WARNING),
            _f("cookies", Severity.WARNING),
        ]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # 3×5=15 raw → security 85
        assert scores["security"] == 85

    def test_tier_score_floors_at_30(self):
        """TIER_FLOOR=30 — i katastrofický tier nespadne pod 30."""
        findings = [_f("secrets", Severity.CRITICAL)] * 20
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        # 20×12=240 raw → floor 30
        assert scores["security"] == 30

    def test_mixed_findings_split_correctly(self):
        findings = [
            _f("headers", Severity.CRITICAL),     # security -12
            _f("legal", Severity.WARNING),        # legal -5
            _f("seo", Severity.INFO),             # seo -1
            _f("accessibility", Severity.WARNING),  # legal -5
        ]
        scores = calculate_tier_scores(findings, accessibility_tier="legal")
        assert scores["security"] == 88  # 100-12
        assert scores["legal"] == 90     # 100 - 5 (legal) - 5 (accessibility)
        assert scores["seo"] == 99       # 100-1


from scanner.score import calculate_overall_score


class TestCalculateOverallScore:
    def test_all_100_equals_100(self):
        scores = {"security": 100, "legal": 100, "seo": 100}
        assert calculate_overall_score(scores) == 100

    def test_all_0_equals_0(self):
        scores = {"security": 0, "legal": 0, "seo": 0}
        assert calculate_overall_score(scores) == 0

    def test_weighted_average_security_only(self):
        """Bezpečnost má váhu 50%, ostatní 100 → 0.5×0 + 0.3×100 + 0.2×100 = 50."""
        scores = {"security": 0, "legal": 100, "seo": 100}
        assert calculate_overall_score(scores) == 50

    def test_weighted_average_legal_only(self):
        """Právní má váhu 30%, ostatní 100 → 0.5×100 + 0.3×0 + 0.2×100 = 70."""
        scores = {"security": 100, "legal": 0, "seo": 100}
        assert calculate_overall_score(scores) == 70

    def test_weighted_average_seo_only(self):
        """SEO má váhu 20%, ostatní 100 → 0.5×100 + 0.3×100 + 0.2×0 = 80."""
        scores = {"security": 100, "legal": 100, "seo": 0}
        assert calculate_overall_score(scores) == 80

    def test_typical_mixed(self):
        """0.5×72 + 0.3×85 + 0.2×60 = 36 + 25.5 + 12 = 73.5 → 74."""
        scores = {"security": 72, "legal": 85, "seo": 60}
        assert calculate_overall_score(scores) == 74

    def test_returns_int(self):
        scores = {"security": 72, "legal": 85, "seo": 60}
        result = calculate_overall_score(scores)
        assert isinstance(result, int)


from scanner.score import resolve_accessibility_tier_from_findings


class TestResolveAccessibilityTier:
    def test_user_override_legal_wins(self):
        findings = []  # bez findings — user řekl legal
        assert resolve_accessibility_tier_from_findings(
            findings, classification="legal"
        ) == "legal"

    def test_user_override_seo_wins(self):
        findings = [
            {"id": "missing-accessibility-statement", "severity": "warning",
             "category": "accessibility"},
        ]
        # I když auto-detekce by řekla legal (severity=warning), user override = seo
        assert resolve_accessibility_tier_from_findings(
            findings, classification="seo"
        ) == "seo"

    def test_auto_legal_when_statement_warning(self):
        """missing-accessibility-statement WARNING = covered sector → legal."""
        findings = [
            {"id": "missing-accessibility-statement", "severity": "warning",
             "category": "accessibility"},
        ]
        assert resolve_accessibility_tier_from_findings(
            findings, classification="auto"
        ) == "legal"

    def test_auto_seo_when_statement_info(self):
        """missing-accessibility-statement INFO = non-covered → seo."""
        findings = [
            {"id": "missing-accessibility-statement", "severity": "info",
             "category": "accessibility"},
        ]
        assert resolve_accessibility_tier_from_findings(
            findings, classification="auto"
        ) == "seo"

    def test_auto_legal_when_statement_ok(self):
        """accessibility-statement-ok znamená, že web má statement.
        Pokud má statement, předpokládáme covered → legal (konzervativní default)."""
        findings = [
            {"id": "accessibility-statement-ok", "severity": "ok",
             "category": "accessibility"},
        ]
        assert resolve_accessibility_tier_from_findings(
            findings, classification="auto"
        ) == "legal"

    def test_auto_default_legal_when_no_accessibility_finding(self):
        """Bez jakéhokoli accessibility findingu → konzervativně legal."""
        findings = [
            {"id": "missing-csp", "severity": "critical", "category": "headers"},
        ]
        assert resolve_accessibility_tier_from_findings(
            findings, classification="auto"
        ) == "legal"


from scanner.score import calculate_vibe_score


class TestCalculateVibeScoreBackwardCompat:
    def test_returns_weighted_average(self):
        """calculate_vibe_score nově vrací vážený průměr per-tier skóre."""
        # security: -12 (headers CRITICAL) → 88
        # legal: nic → 100
        # seo: -1 (seo INFO) → 99
        # Overall: 0.5×88 + 0.3×100 + 0.2×99 = 44 + 30 + 19.8 = 93.8 → 94
        findings = [
            _f("headers", Severity.CRITICAL),
            _f("seo", Severity.INFO),
        ]
        assert calculate_vibe_score(findings) == 94

    def test_no_findings_returns_100(self):
        assert calculate_vibe_score([]) == 100

    def test_default_accessibility_tier_is_legal(self):
        """Bez explicitního accessibility_tier předpokládá legal."""
        findings = [_f("accessibility", Severity.WARNING)]
        # accessibility → legal (default), cap 5
        # legal: -5 → 95
        # security: 100, seo: 100
        # Overall: 0.5×100 + 0.3×95 + 0.2×100 = 50 + 28.5 + 20 = 98.5 → 98 nebo 99
        # round(98.5) v Pythonu = 98 (banker's rounding)
        assert calculate_vibe_score(findings) == 98


from scanner.score import recalculate_with_deep_scan_tiered


class TestRecalculateWithDeepScanTiered:
    def test_returns_dict_with_all_tiers_and_overall(self):
        result = recalculate_with_deep_scan_tiered([], [], classification="auto")
        assert set(result.keys()) == {"security", "legal", "seo", "overall"}
        assert result == {"security": 100, "legal": 100, "seo": 100, "overall": 100}

    def test_security_finding_in_fast_findings(self):
        findings = [
            {"id": "missing-csp", "severity": "critical", "category": "headers"},
        ]
        result = recalculate_with_deep_scan_tiered(findings, [], classification="auto")
        # security: -12 → 88. Overall: 0.5×88 + 0.3×100 + 0.2×100 = 44 + 30 + 20 = 94
        assert result["security"] == 88
        assert result["legal"] == 100
        assert result["seo"] == 100
        assert result["overall"] == 94

    def test_lighthouse_perf_goes_to_seo(self):
        deep = [{"id": "lh-lcp", "severity": "warning", "category": "performance"}]
        result = recalculate_with_deep_scan_tiered([], deep, classification="auto")
        # performance → seo tier. WARNING=5, žádný cap → seo=95.
        # Overall: 0.5×100 + 0.3×100 + 0.2×95 = 50 + 30 + 19 = 99
        assert result["seo"] == 95
        assert result["overall"] == 99

    def test_dismissed_finding_excluded(self):
        findings = [
            {"id": "x", "severity": "critical", "category": "headers", "dismissed": True},
        ]
        result = recalculate_with_deep_scan_tiered(findings, [], classification="auto")
        assert result["overall"] == 100

    def test_user_override_seo_routes_accessibility_to_seo(self):
        findings = [
            {"id": "missing-alt", "severity": "warning", "category": "accessibility"},
        ]
        result = recalculate_with_deep_scan_tiered(findings, [], classification="seo")
        # accessibility → seo, WARNING=5, žádný cap → seo=95
        # Overall: 0.5×100 + 0.3×100 + 0.2×95 = 99
        assert result["seo"] == 95
        assert result["legal"] == 100
        assert result["overall"] == 99

    def test_supersede_dedup_still_works(self):
        """lh-document-title supersedes missing-title — original is excluded."""
        findings = [
            {"id": "missing-title", "severity": "warning", "category": "seo"},
            {"id": "other-seo", "severity": "info", "category": "seo"},
        ]
        deep = [
            {"id": "lh-document-title", "severity": "critical", "category": "seo"},
        ]
        result = recalculate_with_deep_scan_tiered(findings, deep, classification="auto")
        # seo: missing-title vyloučen (superseded). Zbyl other-seo (-1) + lh-doc-title (-12)
        # → seo penalty = 13 → seo=87
        # Overall: 0.5×100 + 0.3×100 + 0.2×87 = 50+30+17.4 = 97.4 → 97
        assert result["seo"] == 87
        assert result["overall"] == 97
